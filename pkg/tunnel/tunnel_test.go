//go:build linux

package tunnel_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	proxyclient "golang.org/x/net/proxy"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
	"github.com/apoxy-dev/apoxy/pkg/utils/vm"
)

func TestTunnelEndToEnd_UserModeClient(t *testing.T) {
	child := vm.RunTestInVM(t)
	if !child {
		return
	}

	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	certsDir := t.TempDir()

	// Save the server certificate and private key to the temporary directory as PEM files
	err = cryptoutils.SaveCertificatePEM(serverCert, certsDir, "server", false)
	require.NoError(t, err)

	// Create a client UUID and JWT token
	// This UUID is used to identify the client in the server's tunnel node list.
	// The JWT token is used for authentication and contains the client's UUID as the subject.
	clientUUID := uuid.New()

	jwtPrivateKeyPEM, jwtPublicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	jwtPrivateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(jwtPrivateKeyPEM)
	require.NoError(t, err)

	clientAuthToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": clientUUID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	}).SignedString(jwtPrivateKey)
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha.Install(scheme))

	clientTunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "client",
			UID:  types.UID(clientUUID.String()),
		},
		Status: corev1alpha.TunnelNodeStatus{
			Credentials: &corev1alpha.TunnelNodeCredentials{
				Token: clientAuthToken,
			},
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(clientTunnelNode).WithStatusSubresource(clientTunnelNode).Build()

	jwtValidator, err := token.NewInMemoryValidator(jwtPublicKeyPEM)
	require.NoError(t, err)

	serverRouter, err := router.NewNetlinkRouter()
	require.NoError(t, err)

	server, err := tunnel.NewTunnelServer(
		kubeClient,
		jwtValidator,
		serverRouter,
		tunnel.WithCertPath(filepath.Join(certsDir, "server.crt")),
		tunnel.WithKeyPath(filepath.Join(certsDir, "server.key")),
		tunnel.WithIPAMv4(tunnet.NewIPAMv4(context.Background())),
	)
	require.NoError(t, err)

	// Register the client with the server via reconcile
	_, err = server.ReconcileWithClient(ctx, kubeClient, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: clientTunnelNode.Name},
	})
	require.NoError(t, err)

	g, ctx := errgroup.WithContext(ctx)

	// Start a little http server listening on the client side.
	httpListener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Hello, world!")
		}),
	}

	g.Go(func() error {
		g.Go(func() error {
			<-ctx.Done()
			t.Log("Closing HTTP test server")
			return httpServer.Close()
		})

		defer t.Log("HTTP test server closed")
		t.Log("Starting HTTP test server")

		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("unable to start HTTP server: %v", err)
		}

		return nil
	})

	// Start the server.
	g.Go(func() error {
		defer t.Log("Tunnel server closed")

		t.Log("Starting tunnel server")

		if err := server.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("unable to start server: %v", err)
		}

		return nil
	})

	var r router.Router
	// Start the router.
	g.Go(func() error {
		defer t.Log("Tunnel client closed")

		// Wait for the server to start.
		time.Sleep(1 * time.Second)

		t.Log("Starting tunnel client")

		var err error
		r, err = tunnel.BuildClientRouter(
			tunnel.WithRootCAs(cryptoutils.CertPoolForCertificate(caCert)),
			tunnel.WithSocksListenAddr("localhost:1081"),
			tunnel.WithPcapPath("client.pcap"),
		)
		require.NoError(t, err)

		err = r.Start(ctx)
		require.NoError(t, err)

		return nil
	})

	d := &tunnel.TunnelDialer{Router: r}
	conn, err := d.Dial(
		ctx,
		uuid.New(),
		"localhost:9443",
		tunnel.WithAuthToken(clientAuthToken),
	)
	require.NoError(t, err)

	// Run the test.
	g.Go(func() error {
		defer cancel()

		var addrs []netip.Prefix
		err := retry.Do(
			func() error {
				var err error
				addrs, err = conn.LocalAddrs()
				if err != nil {
					return err
				}
				if len(addrs) == 0 {
					return fmt.Errorf("no addresses yet")
				}
				return nil
			},
			retry.Context(ctx),
			retry.Attempts(10),
			retry.Delay(time.Second),
		)
		if err != nil {
			return fmt.Errorf("failed to get client addresses: %w", err)
		}

		t.Logf("Assigned client addresses: %v", addrs)

		t.Log("Connecting to HTTP server running on client via the tunnel")

		httpPort := httpListener.Addr().(*net.TCPAddr).Port
		resp, err := http.Get("http://" + net.JoinHostPort(addrs[0].Addr().String(), fmt.Sprintf("%d", httpPort)))
		require.NoError(t, err)
		defer resp.Body.Close()

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Hello, world!\n", string(body))

		t.Log("Connection successful")

		return nil
	})

	require.NoError(t, g.Wait())
}

func TestTunnelEndToEnd_KernelModeClient(t *testing.T) {
	child := vm.RunTestInVM(t)
	if !child {
		return
	}

	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	certsDir := t.TempDir()

	// Save the server certificate and private key to the temporary directory as PEM files
	err = cryptoutils.SaveCertificatePEM(serverCert, certsDir, "server", false)
	require.NoError(t, err)

	// Create a client UUID and JWT token
	// This UUID is used to identify the client in the server's tunnel node list.
	// The JWT token is used for authentication and contains the client's UUID as the subject.
	clientUUID := uuid.New()

	jwtPrivateKeyPEM, jwtPublicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	jwtPrivateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(jwtPrivateKeyPEM)
	require.NoError(t, err)

	clientAuthToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": clientUUID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	}).SignedString(jwtPrivateKey)
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha.Install(scheme))

	clientTunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "client",
			UID:  types.UID(clientUUID.String()),
		},
		Status: corev1alpha.TunnelNodeStatus{
			Credentials: &corev1alpha.TunnelNodeCredentials{
				Token: clientAuthToken,
			},
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(clientTunnelNode).WithStatusSubresource(clientTunnelNode).Build()

	jwtValidator, err := token.NewInMemoryValidator(jwtPublicKeyPEM)
	require.NoError(t, err)

	serverRouter, err := router.NewNetstackRouter(
		// We need to assign atleast one local address to the server for netstack to work.
		router.WithLocalAddresses([]netip.Prefix{
			netip.MustParsePrefix("fd00::/64"),
		}),
		router.WithPcapPath("server.pcap"),
	)
	require.NoError(t, err)

	server, err := tunnel.NewTunnelServer(
		kubeClient,
		jwtValidator,
		serverRouter,
		tunnel.WithCertPath(filepath.Join(certsDir, "server.crt")),
		tunnel.WithKeyPath(filepath.Join(certsDir, "server.key")),
		tunnel.WithIPAMv4(tunnet.NewIPAMv4(context.Background())),
	)
	require.NoError(t, err)

	// Register the client with the server via reconcile
	_, err = server.ReconcileWithClient(ctx, kubeClient, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: clientTunnelNode.Name},
	})
	require.NoError(t, err)

	g, ctx := errgroup.WithContext(ctx)

	var r router.Router
	// Start the router.
	g.Go(func() error {
		defer t.Log("Tunnel client closed")

		// Wait for the server to start.
		time.Sleep(1 * time.Second)

		t.Log("Starting tunnel client")

		var err error
		r, err = tunnel.BuildClientRouter(
			tunnel.WithRootCAs(cryptoutils.CertPoolForCertificate(caCert)),
			tunnel.WithMode(tunnel.TunnelClientModeKernel),
			tunnel.WithPcapPath("client.pcap"),
		)
		require.NoError(t, err)

		err = r.Start(ctx)
		require.NoError(t, err)

		return nil
	})

	// Start the server.
	g.Go(func() error {
		defer t.Log("Tunnel server closed")

		t.Log("Starting tunnel server")

		if err := server.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("unable to start server: %v", err)
		}

		return nil
	})

	d := &tunnel.TunnelDialer{Router: r}
	conn, err := d.Dial(
		ctx,
		uuid.New(),
		"localhost:9443",
		tunnel.WithAuthToken(clientAuthToken),
	)
	require.NoError(t, err)

	var httpListener net.Listener
	g.Go(func() error {
		var addrs []netip.Prefix
		err := retry.Do(
			func() error {
				var err error
				addrs, err = conn.LocalAddrs()
				if err != nil {
					return err
				}
				if len(addrs) == 0 {
					return fmt.Errorf("no addresses yet")
				}
				return nil
			},
			retry.Context(ctx),
			retry.Attempts(10),
			retry.Delay(time.Second),
		)
		if err != nil {
			return fmt.Errorf("failed to get client addresses: %w", err)
		}

		// Start a little http server listening on the client side.
		httpListener, err = net.Listen("tcp", net.JoinHostPort(addrs[0].Addr().String(), "0"))
		require.NoError(t, err)

		httpServer := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, "Hello, world!")
			}),
		}

		g.Go(func() error {
			<-ctx.Done()
			t.Log("Closing HTTP test server")
			return httpServer.Close()
		})

		defer t.Log("HTTP test server closed")
		t.Log("Starting HTTP test server")

		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("unable to start HTTP server: %v", err)
		}

		return nil
	})

	g.Go(func() error {
		// Cancel the context when the test is done
		defer cancel()

		err := retry.Do(
			func() error {
				if httpListener == nil {
					return fmt.Errorf("http listener not ready")
				}
				return nil
			},
			retry.Context(ctx),
			retry.Attempts(10),
			retry.Delay(1*time.Second),
		)
		if err != nil {
			return fmt.Errorf("listener never became ready: %w", err)
		}

		t.Logf("Connecting to HTTP server running on client via the tunnel: %s",
			httpListener.Addr().(*net.TCPAddr).String())

		dialer, err := proxyclient.SOCKS5("tcp", "localhost:1080", nil, proxyclient.Direct)
		require.NoError(t, err)

		client := &http.Client{
			Transport: &http.Transport{
				Dial: dialer.Dial,
			},
		}

		resp, err := client.Get("http://" + httpListener.Addr().(*net.TCPAddr).String())
		require.NoError(t, err)
		defer resp.Body.Close()

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Hello, world!\n", string(body))

		t.Log("Connection successful")

		return nil
	})

	require.NoError(t, g.Wait())
}
