package apiserviceproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/apoxy-dev/apoxy/pkg/cert/reload"
)

const (
	// Default Cosmos API host.
	defaultAPIHost = "api.apoxy.dev"
	// APIServer APIs.
	defaultAPIProxyHost      = "apiz.apoxy.dev"
	kubeControllerUserPrefix = "kube-controller-"

	apizCertSecretName          = "apiz-cert"
	apiServiceServingSecretName = "apiservice-serving-cert"
	tlsSecretCert               = "tls.crt"
	tlsSecretKey                = "tls.key"
	tlsSecretCA                 = "ca.crt"

	// DefaultCertDir is the in-pod mount path of the apiz-cert Secret.
	// The apoxy-cloud onboarding manifest must mount the Secret at this
	// path for hot-reload to engage. If the mount is absent the watcher
	// no-ops and falls back to the legacy restart-driven rotation.
	DefaultCertDir = "/etc/apoxy/certs"

	// Apoxy API headers.
	ApoxyAPIKeyHeaderKey    = "x-apoxy-api-key"
	ApoxyProjectIdHeaderKey = "x-apoxy-project-id"
	ApoxyServiceUserKey     = "x-apoxy-service-user"
)

// IssueClientCertResponse is the response from the certificate issuance endpoint.
// Field names use camelCase to match gRPC-gateway's default protojson output.
type IssueClientCertResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	CA          string `json:"ca"`
}

func (p *APIServiceProxy) configureCloudProxy(ctx context.Context) error {
	log.Printf("configuring cloud proxy for project %s", p.opts.ProjectID)

	remote, err := url.Parse(fmt.Sprintf("https://%s", resolveAPIProxyHost(p.opts.ProjectID, p.opts.APIHost)))
	if err != nil {
		return fmt.Errorf("failed to parse remote URL: %w", err)
	}
	p.proxy = newCloudReverseProxy(remote)

	if err := p.ensureServingCertificate(ctx); err != nil {
		return fmt.Errorf("failed to ensure serving certificate: %w", err)
	}

	boot, err := p.loadUpstreamCertificate(ctx)
	if err != nil {
		log.Printf("existing upstream certificate is invalid, re-issuing: %v", err)
	}
	if boot == nil {
		boot, err = p.issueCertificate(ctx)
		if err != nil {
			return fmt.Errorf("failed to issue certificate: %w", err)
		}
	}

	// On first boot the Secret is created here by issueCertificate and the
	// kubelet projection lags by up to ~60s; seed from this in-memory
	// bundle and let the watcher take over once the file lands.
	p.certStore = reload.NewStore()
	p.certStore.Store(boot)
	certExpiry.Set(float64(boot.NotAfter.Unix()))

	p.transport = newSwappableTransport(buildTransport(boot, p.opts.LocalMode))
	p.proxy.Transport = newDiscoveryCacheTransport(p.transport, defaultDiscoveryCacheTTL)

	// Hot-reload is engaged only when the Secret is mounted at CertDir; an
	// older onboarding manifest that doesn't mount it falls back to the
	// legacy restart-driven rotation.
	if p.opts.CertDir != "" {
		go func() {
			err := reload.Watch(ctx, reload.FromDir(p.opts.CertDir), p.certStore, reload.WatchOptions{
				Component: "kube-controller",
				Metrics:   certReloadMetrics{},
				OnSwap: func(b *reload.Bundle) {
					old := p.transport.Store(buildTransport(b, p.opts.LocalMode))
					// Drop the old idle-conn pool so we don't leak file
					// descriptors across rotations. In-flight requests still
					// finish on their existing TCP connections.
					old.CloseIdleConnections()
				},
			})
			if err != nil {
				slog.Error("Cert watcher exited with error", "err", err)
			}
		}()
	} else {
		slog.Info("Upstream cert hot-reload disabled (no cert dir configured)")
	}

	return nil
}

func resolveAPIProxyHost(projectID uuid.UUID, apiHost string) string {
	host := resolveBaseAPIProxyHost(apiHost)
	if projectID == uuid.Nil {
		return host
	}
	projectPrefix := projectID.String() + "."
	if strings.HasPrefix(host, projectPrefix) {
		return host
	}
	if strings.HasPrefix(host, "apiz.") || strings.HasPrefix(host, "apiz-") {
		return projectPrefix + host
	}
	return host
}

func resolveBaseAPIProxyHost(apiHost string) string {
	switch {
	case apiHost == "", apiHost == defaultAPIHost:
		return defaultAPIProxyHost
	case strings.HasPrefix(apiHost, "apiz."), strings.HasPrefix(apiHost, "apiz-"):
		return apiHost
	case strings.HasPrefix(apiHost, "api."):
		return "apiz." + strings.TrimPrefix(apiHost, "api.")
	case strings.HasPrefix(apiHost, "api-"):
		return "apiz-" + strings.TrimPrefix(apiHost, "api-")
	default:
		return apiHost
	}
}

func newCloudReverseProxy(remote *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.ErrorLog = newReverseProxyErrorLogger()
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = remote.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("api service proxy upstream error for %s %s: %v", req.Method, req.URL.String(), err)
		w.WriteHeader(http.StatusBadGateway)
	}
	return proxy
}

// loadUpstreamCertificate reads + parses the upstream client cert from the
// existing apiz-cert Secret. Returns (nil, nil) if the Secret is missing —
// the caller treats that as "first boot, mint a new one."
func (p *APIServiceProxy) loadUpstreamCertificate(ctx context.Context) (*reload.Bundle, error) {
	log.Printf("loading certificate for project %s", p.opts.ProjectID)

	secret, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Get(ctx, apizCertSecretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return reload.BundleFromPEM(secret.Data[tlsSecretCert], secret.Data[tlsSecretKey], secret.Data[tlsSecretCA])
}

func (p *APIServiceProxy) saveCertificate(ctx context.Context, certPem, keyPem, caPem []byte) error {
	return saveApizCertSecret(ctx, p.kC, p.opts.Namespace, certPem, keyPem, caPem)
}

// saveApizCertSecret writes (or updates) the apiz-cert Secret in the given
// namespace. Update is guarded by ResourceVersion so concurrent rotators
// (e.g. manual `apoxy k8s certs rotate` racing the auto-renewer) fail loudly
// rather than silently clobbering each other.
func saveApizCertSecret(ctx context.Context, kc kubernetes.Interface, namespace string, certPem, keyPem, caPem []byte) error {
	certSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: apizCertSecretName,
		},
		Data: map[string][]byte{
			tlsSecretCert: certPem,
			tlsSecretKey:  keyPem,
			tlsSecretCA:   caPem,
		},
		Type: corev1.SecretTypeTLS,
	}

	if _, err := kc.CoreV1().Secrets(namespace).Create(ctx, certSecret, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
		existing, getErr := kc.CoreV1().Secrets(namespace).Get(ctx, apizCertSecretName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		certSecret.ResourceVersion = existing.ResourceVersion
		if _, err := kc.CoreV1().Secrets(namespace).Update(ctx, certSecret, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (p *APIServiceProxy) issueCertificate(ctx context.Context) (*reload.Bundle, error) {
	log.Printf("issuing certificate for project %s", p.opts.ProjectID)

	host := p.opts.APIHost
	if host == "" {
		host = defaultAPIHost
	}
	client := http.DefaultClient
	if p.opts.LocalMode {
		// Cosmos serving cert in dev is cert-manager self-signed and not in
		// the pod trust store; skip verification rather than mounting the
		// dev CA into every kube-controller pod.
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	return doIssueCertificate(ctx, client, host, map[string]string{
		ApoxyAPIKeyHeaderKey:    p.opts.Token,
		ApoxyProjectIdHeaderKey: p.opts.ProjectID.String(),
		ApoxyServiceUserKey:     kubeControllerUserPrefix + p.opts.ClusterName,
	}, p.kC, p.opts.Namespace)
}

// doIssueCertificate POSTs to cosmos's IssueServiceCert endpoint, validates
// the returned PEMs, persists them to the apiz-cert Secret, and returns the
// new bundle. Shared by the bootstrap path (API-key auth, api.* host) and
// the renewal path (mTLS auth, apiz.* host).
func doIssueCertificate(ctx context.Context, client *http.Client, host string, headers map[string]string, kc kubernetes.Interface, namespace string) (*reload.Bundle, error) {
	addr := fmt.Sprintf("https://%s/v1/terra/serviceaccount/certificate", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issue cert: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read issue-cert response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issue cert: status %d: %s", resp.StatusCode, string(body))
	}

	var certResp IssueClientCertResponse
	if err := json.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("decode issue-cert response: %w", err)
	}

	certPEM, keyPEM, caPEM := []byte(certResp.Certificate), []byte(certResp.PrivateKey), []byte(certResp.CA)
	if err := saveApizCertSecret(ctx, kc, namespace, certPEM, keyPEM, caPEM); err != nil {
		return nil, fmt.Errorf("save issued cert secret: %w", err)
	}
	return reload.BundleFromPEM(certPEM, keyPEM, caPEM)
}

func (p *APIServiceProxy) ensureServingCertificate(ctx context.Context) error {
	ok, err := p.loadServingCertificate(ctx)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	cert, certPEM, keyPEM, caPEM, err := generateServingCertificate(p.opts.ServiceName, p.opts.Namespace)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: apiServiceServingSecretName,
		},
		Data: map[string][]byte{
			tlsSecretCert: certPEM,
			tlsSecretKey:  keyPEM,
			tlsSecretCA:   caPEM,
		},
		Type: corev1.SecretTypeTLS,
	}
	if _, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return err
		}
		ok, loadErr := p.loadServingCertificate(ctx)
		if loadErr != nil {
			return loadErr
		}
		if !ok {
			return fmt.Errorf("serving certificate secret %q already exists but could not be loaded", apiServiceServingSecretName)
		}
		return nil
	}

	p.servingCert = cert
	p.caBundle = caPEM
	return nil
}

func (p *APIServiceProxy) loadServingCertificate(ctx context.Context) (bool, error) {
	secret, err := p.kC.CoreV1().Secrets(p.opts.Namespace).Get(ctx, apiServiceServingSecretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	cert, err := tls.X509KeyPair(secret.Data[tlsSecretCert], secret.Data[tlsSecretKey])
	if err != nil {
		return false, err
	}
	p.servingCert = cert
	p.caBundle = append([]byte(nil), secret.Data[tlsSecretCA]...)
	return true, nil
}
