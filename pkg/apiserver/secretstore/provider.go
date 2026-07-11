package secretstore

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	registryrest "k8s.io/apiserver/pkg/registry/rest"

	serverapiserver "github.com/apoxy-dev/apoxy/pkg/apiserver/server/apiserver"
)

// ValuesSubResource is the subresource name under secretstores.
const ValuesSubResource = "values"

// RedactedProvider wraps a genericregistry.Store-producing provider (the
// builder's standard kine-backed one) so main-resource responses never carry
// stored secret values.
func RedactedProvider(base serverapiserver.StorageProvider) serverapiserver.StorageProvider {
	return func(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (registryrest.Storage, error) {
		storage, err := base(scheme, optsGetter)
		if err != nil {
			return nil, err
		}
		store, ok := storage.(*genericregistry.Store)
		if !ok {
			return nil, fmt.Errorf("secretstore main storage must be *registry.Store, got %T", storage)
		}
		return &redactedStorage{Store: store}, nil
	}
}

// ValuesProvider mounts the values subresource over the same logical store:
// it instantiates the base provider (a second registry.Store against the same
// backend, exactly like the builder's status-subresource path) and swaps in
// the values update strategy.
func ValuesProvider(base serverapiserver.StorageProvider) serverapiserver.StorageProvider {
	return func(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (registryrest.Storage, error) {
		storage, err := base(scheme, optsGetter)
		if err != nil {
			return nil, err
		}
		store, ok := storage.(*genericregistry.Store)
		if !ok {
			return nil, fmt.Errorf("secretstore values storage must be *registry.Store, got %T", storage)
		}
		valuesStore := *store
		valuesStore.UpdateStrategy = valuesUpdateStrategy{RESTUpdateStrategy: store.UpdateStrategy}
		return &valuesStorage{store: &valuesStore}, nil
	}
}

// ReadAuthz decides whether an authenticated identity may read secret values.
type ReadAuthz func(user.Info) bool

// AllowAllReads is the single-node/OSS default: the local apiserver is a
// single-user trust domain (the backing SQLite file sits on the same disk),
// so value reads are not restricted. Redacted main-resource reads remain for
// interface consistency with hosted deployments.
func AllowAllReads(user.Info) bool { return true }

// NewValuesReadAuthorizer wraps an authorizer and denies reads of the values
// subresource unless the identity passes allow. Writes (update/patch) are not
// restricted here — any project identity may set values it can never read
// back. Enforcing at the authorization layer (rather than in storage) keeps
// the PATCH flow intact: the patch handler's internal storage Get is not a
// separately authorized request.
func NewValuesReadAuthorizer(delegate authorizer.Authorizer, allow ReadAuthz) authorizer.Authorizer {
	if allow == nil {
		allow = AllowAllReads
	}
	return authorizer.AuthorizerFunc(func(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
		if attrs.IsResourceRequest() &&
			attrs.GetResource() == "secretstores" &&
			attrs.GetSubresource() == ValuesSubResource {
			switch attrs.GetVerb() {
			case "get", "list", "watch":
				if !allow(attrs.GetUser()) {
					return authorizer.DecisionDeny, "secret values are write-only for this identity", nil
				}
			}
		}
		return delegate.Authorize(ctx, attrs)
	})
}
