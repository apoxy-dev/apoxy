package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	tunnet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// maxNetworkID is the exclusive upper bound of the 24-bit NetworkID space.
const maxNetworkID = 1 << 24

// tokenLength is the byte length of a minted connect credential (32 bytes ->
// 43-char base64 string).
const tokenLength = 32

// generateBearerToken returns a cryptographically random URL-safe bearer token
// of n bytes.
func generateBearerToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var _ reconcile.Reconciler = &VPCNetworkReconciler{}

// VPCNetworkReconciler is the standalone (OSS/single-tenant) provisioner for
// VPCNetworks: it assigns each network a 24-bit NetworkID and its overlay /72,
// mints the network's connect credential, and marks it Ready. In cloud this
// role is played by the infra-backed VPCNetworkProvisioner (APO-746); the API
// surface is identical so the relay wiring is the same in both modes. It is the
// sole writer of a network's identity and credential.
type VPCNetworkReconciler struct {
	client.Client
	// apiReader is the uncached client used for NetworkID assignment; set in
	// SetupWithManager.
	apiReader client.Reader
}

// NewVPCNetworkReconciler creates the OSS VPCNetwork provisioner. apiReader
// defaults to the cached client and is replaced with the manager's uncached
// reader in SetupWithManager so NetworkID assignment sees fresh writes.
func NewVPCNetworkReconciler(c client.Client) *VPCNetworkReconciler {
	return &VPCNetworkReconciler{Client: c, apiReader: c}
}

// Reconcile assigns identity + credential to a VPCNetwork and marks it Ready.
func (r *VPCNetworkReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := controllerlog.FromContext(ctx, "network", req.Name)

	var network vpcv1alpha1.VPCNetwork
	if err := r.Get(ctx, req.NamespacedName, &network); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	changed := false

	// Assign the overlay /72 (write-once: an existing CIDR is never reassigned).
	if network.Status.OverlayCIDR == "" {
		id, err := r.assignNetworkID(ctx)
		if err != nil {
			return reconcile.Result{}, err
		}
		network.Status.OverlayCIDR = tunnet.NetworkPrefix(id).String()
		log.Info("Assigned network overlay", "cidr", network.Status.OverlayCIDR)
		changed = true
	}

	// Mint the connect credential once.
	if network.Status.Credentials == nil || network.Status.Credentials.Token == "" {
		token, err := generateBearerToken(tokenLength)
		if err != nil {
			return reconcile.Result{}, err
		}
		network.Status.Credentials = &vpcv1alpha1.VPCNetworkCredentials{Token: token}
		log.Info("Minted network connect credential")
		changed = true
	}

	if meta.SetStatusCondition(&network.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "Provisioned",
		Message: "Network identity and credential assigned",
	}) {
		changed = true
	}

	if changed {
		if err := r.Status().Update(ctx, &network); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// assignNetworkID picks the lowest unused 24-bit NetworkID, reserving the
// system id (0). Assignment is stateless: the source of truth is the set of
// overlay CIDRs already written to VPCNetwork objects.
func (r *VPCNetworkReconciler) assignNetworkID(ctx context.Context) (tunnet.NetworkID, error) {
	var list vpcv1alpha1.VPCNetworkList
	if err := r.apiReader.List(ctx, &list); err != nil {
		return tunnet.NetworkID{}, err
	}

	used := map[tunnet.NetworkID]bool{tunnet.SystemNetworkID: true}
	for i := range list.Items {
		cidr := list.Items[i].Status.OverlayCIDR
		if cidr == "" {
			continue
		}
		if id, err := tunnet.NetworkIDFromCIDR(cidr); err == nil {
			used[id] = true
		}
	}

	for i := 1; i < maxNetworkID; i++ {
		id := tunnet.NetworkID{byte(i >> 16), byte(i >> 8), byte(i)}
		if !used[id] {
			return id, nil
		}
	}
	return tunnet.NetworkID{}, fmt.Errorf("network id space exhausted")
}

// SetupWithManager wires the provisioner to VPCNetwork objects.
func (r *VPCNetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// NetworkID assignment reads through the uncached API reader so a network's
	// just-written OverlayCIDR is visible on the next reconcile; the informer
	// cache lags, which would let two networks claim the same id.
	r.apiReader = mgr.GetAPIReader()
	return ctrl.NewControllerManagedBy(mgr).
		Named("vpcnetwork-provisioner").
		For(&vpcv1alpha1.VPCNetwork{}).
		Complete(r)
}
