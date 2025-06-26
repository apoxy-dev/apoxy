package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/apoxy-dev/apoxy/client/versioned"
	"github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/tunnel"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

const (
	matchingTunnelNodesIndex = "remoteTunnelNodeIndex"

	tunnelNodeEpochLabel = "core.apoxy.dev/tunnelnode-epoch"
)

var (
	scheme       = runtime.NewScheme()
	codecFactory = serializer.NewCodecFactory(scheme)
	decodeFn     = codecFactory.UniversalDeserializer().Decode

	tunnelNodePcapPath string
	tunnelModeS        string
	tunnelMode         tunnel.TunnelClientMode
)

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
}

type tunnelNodeReconciler struct {
	client.Client

	scheme *runtime.Scheme
	cfg    *configv1alpha1.Config
	a3y    versioned.Interface
	doneCh chan error

	tunC *tunnel.TunnelClient
}

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		var err error
		tunnelMode, err = tunnel.TunnelClientModeFromString(tunnelModeS)
		if err != nil {
			return fmt.Errorf("unable to parse tunnel client mode: %w", err)
		}

		cmd.SilenceUsage = true

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}

		a3y, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		tunnelNodeName := args[0]
		tn, err := a3y.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}

		tun := &tunnelNodeReconciler{
			scheme: scheme,
			cfg:    cfg,
			a3y:    a3y,

			doneCh: make(chan error),
		}
		return tun.run(ctx, tn)
	},
}

func (t *tunnelNodeReconciler) run(ctx context.Context, tn *corev1alpha.TunnelNode) error {
	slog.Debug("Running TunnelNode controller", slog.String("name", tn.Name))

	client, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	mgr, err := ctrl.NewManager(client.RESTConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set up overall controller manager: %w", err)
	}

	t.Client = mgr.GetClient()
	if err := t.setupWithManager(ctx, mgr, tn.Name); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}

	go func() {
		defer close(t.doneCh)
		if err := mgr.Start(ctx); err != nil {
			slog.Error("Manager exited non-zero", slog.Any("error", err))
		}
	}()

	// Set the initial status of the TunnelNode object.
	// Wait for the TunnelNode object to be deleted, or for the command to be cancelled.
	select {
	case err := <-t.doneCh:
		if err != nil {
			return fmt.Errorf("manager exited non-zero: %w", err)
		}
	case <-ctx.Done():
	}

	<-t.doneCh // Wait for manager go-routine to exist.

	if t.tunC != nil {
		if err := t.tunC.Close(); err != nil {
			slog.Error("Failed to stop tunnel client", slog.Any("error", err))
		}
	}

	return nil
}

func targetRefPredicate(tunnelNodeName string) predicate.Funcs {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}
		return obj.GetName() == tunnelNodeName
	})
}

func (t *tunnelNodeReconciler) setupWithManager(
	ctx context.Context,
	mgr ctrl.Manager,
	tunnelNodeName string,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(
			&corev1alpha.TunnelNode{},
			builder.WithPredicates(
				predicate.GenerationChangedPredicate{},
				targetRefPredicate(tunnelNodeName),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(t)
}

func (t *tunnelNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	var tunnelNode corev1alpha.TunnelNode
	if err := t.Get(ctx, req.NamespacedName, &tunnelNode); err != nil {
		if client.IgnoreNotFound(err) == nil {
			t.doneCh <- errors.New("TunnelNode not found")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get TunnelNode")
		return ctrl.Result{}, err
	}

	cOpts := []tunnel.TunnelClientOption{
		tunnel.WithPcapPath(tunnelNodePcapPath),
		tunnel.WithMode(tunnelMode),
	}
	tnUUID, err := uuid.Parse(string(tunnelNode.ObjectMeta.UID))
	if err != nil { // This can only happen in a test environment.
		log.Error(err, "Failed to parse UID", "uid", tunnelNode.ObjectMeta.UID)
		return ctrl.Result{}, err
	} else {
		cOpts = append(cOpts, tunnel.WithUUID(tnUUID))
	}
	if tunnelNode.Status.Credentials == nil || tunnelNode.Status.Credentials.Token == "" {
		log.Info("TunnelNode has no credentials")
		return ctrl.Result{
			RequeueAfter: time.Second,
		}, nil
	} else {
		cOpts = append(cOpts, tunnel.WithAuthToken(tunnelNode.Status.Credentials.Token))
	}
	if !t.cfg.IsLocalMode { // Keep default server address in local mode.
		if len(tunnelNode.Status.Addresses) == 0 {
			log.Info("TunnelNode has no addresses")
			return ctrl.Result{
				RequeueAfter: time.Second,
			}, nil
		} else {
			cOpts = append(cOpts, tunnel.WithServerAddr(tunnelNode.Status.Addresses[rand.Intn(len(tunnelNode.Status.Addresses))]))
		}
	}
	if t.cfg.IsLocalMode {
		cOpts = append(cOpts, tunnel.WithInsecureSkipVerify(true))
	}

	if t.tunC != nil {
		log.Info("Closing existing tunnel client")
		if err := t.tunC.Close(); err != nil {
			log.Error(err, "Failed to close existing tunnel client")
		}
		t.tunC = nil
	}

	if t.tunC, err = tunnel.NewTunnelClient(cOpts...); err != nil {
		log.Error(err, "Failed to create tunnel client")
		t.doneCh <- fmt.Errorf("failed to create tunnel client: %w", err)
		return ctrl.Result{}, nil // Unrecoverable error.
	}

	go func() {
		if err := t.tunC.Start(ctx); err != nil {
			log.Error(err, "Failed to start tunnel client")
			t.doneCh <- fmt.Errorf("failed to start tunnel client: %w", err)
		}
	}()

	return ctrl.Result{}, nil
}
