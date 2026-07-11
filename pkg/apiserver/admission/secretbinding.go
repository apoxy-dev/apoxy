package admission

import (
	"context"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	a3yclient "github.com/apoxy-dev/apoxy/client/versioned"
)

// SecretBindingPluginName identifies the compute secret-binding validation
// plugin in the admission chain.
const SecretBindingPluginName = "ComputeSecretBindings"

// computeServiceLabel links a minted ServiceRevision to its Service; it is
// set by the compute ServiceReconciler and used here to name the consumer
// for scope checks on revision writes.
const computeServiceLabel = "compute.apoxy.dev/service"

// NewSecretBindingPlugin validates the secret bindings of compute Services
// and ServiceRevisions on write: the referenced SecretStore must exist, its
// scopes must admit the service on the "compute" surface, and the bound key
// must be present in the store. This makes `apoxy apply` fail fast; the
// data-plane resolver re-checks at materialization time to cover stores that
// change after admission.
func NewSecretBindingPlugin() admission.Factory {
	return func(io.Reader) (admission.Interface, error) {
		return &secretBindingPlugin{
			Handler: admission.NewHandler(admission.Create, admission.Update),
		}, nil
	}
}

type secretBindingPlugin struct {
	*admission.Handler
	client a3yclient.Interface
}

var (
	_ admission.ValidationInterface = &secretBindingPlugin{}
	_ WantsApoxyClient              = &secretBindingPlugin{}
)

func (p *secretBindingPlugin) SetApoxyClient(c a3yclient.Interface) {
	p.client = c
}

func (p *secretBindingPlugin) ValidateInitialization() error {
	if p.client == nil {
		return fmt.Errorf("%s: missing apoxy client", SecretBindingPluginName)
	}
	return nil
}

func (p *secretBindingPlugin) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if a.GetSubresource() != "" {
		return nil
	}

	var (
		consumer string
		bindings []computev1alpha1.Binding
	)
	switch obj := a.GetObject().(type) {
	case *computev1alpha1.Service:
		consumer = obj.Name
		bindings = obj.Spec.Template.Spec.Bindings
	case *computev1alpha1.ServiceRevision:
		// Revisions are minted by the reconciler from an already-admitted
		// Service; the check here is defense in depth. The owning Service's
		// name travels on the revision label.
		consumer = obj.Labels[computeServiceLabel]
		bindings = obj.Spec.Bindings
	default:
		return nil
	}

	for i := range bindings {
		b := &bindings[i]
		if b.Type != computev1alpha1.SecretBindingType || b.Secret == nil {
			continue
		}
		store, err := p.client.CoreV1alpha().SecretStores().Get(ctx, string(b.Secret.Store), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return admission.NewForbidden(a, fmt.Errorf(
				"binding %q references SecretStore %q which does not exist; create the SecretStore first",
				b.Name, b.Secret.Store))
		}
		if err != nil {
			return fmt.Errorf("checking SecretStore %q for binding %q: %w", b.Secret.Store, b.Name, err)
		}
		if consumer != "" && !store.ScopeAllows("compute", consumer) {
			return admission.NewForbidden(a, fmt.Errorf(
				"binding %q: SecretStore %q scopes %v do not admit compute service %q",
				b.Name, b.Secret.Store, store.Spec.Scopes, consumer))
		}
		if !hasKey(store, b.Secret.Key) {
			return admission.NewForbidden(a, fmt.Errorf(
				"binding %q: SecretStore %q has no key %q; set it with `apoxy secret set %s %s`",
				b.Name, b.Secret.Store, b.Secret.Key, b.Secret.Store, b.Secret.Key))
		}
	}
	return nil
}

// hasKey checks key presence via status — admission reads through the
// redacted API surface and never needs values.
func hasKey(store *corev1alpha.SecretStore, key string) bool {
	for _, k := range store.Status.Keys {
		if k.Name == key {
			return true
		}
	}
	return false
}
