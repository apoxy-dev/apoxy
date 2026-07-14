package v1alpha1

import (
	"context"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

var (
	_ resourcestrategy.Validater       = &Service{}
	_ resourcestrategy.ValidateUpdater = &Service{}
	_ resourcestrategy.Validater       = &ServiceRevision{}
	_ resourcestrategy.ValidateUpdater = &ServiceRevision{}
	_ resourcestrategy.Validater       = &Build{}
	_ resourcestrategy.ValidateUpdater = &Build{}
)

// =============================================================================
// Service
// =============================================================================

func (w *Service) Validate(_ context.Context) field.ErrorList {
	return validateServiceSpec(&w.Spec, field.NewPath("spec"))
}

// ValidateUpdate runs full validation on the new object and additionally
// enforces that the runtime mode is immutable. The receiver is the new object;
// old is the stored one.
func (w *Service) ValidateUpdate(ctx context.Context, old runtime.Object) field.ErrorList {
	errs := w.Validate(ctx)
	oldW, ok := old.(*Service)
	if !ok {
		return errs
	}
	if oldW.Spec.Template.Spec.Mode() != w.Spec.Template.Spec.Mode() {
		errs = append(errs, field.Forbidden(
			field.NewPath("spec", "template"),
			"runtime mode is immutable; create a new Service to switch between backend and filter"))
	}
	return errs
}

func validateServiceSpec(spec *ServiceSpec, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	// Source is the single bundle origin: exactly one of oci (push) or git.
	errs = append(errs, validateSource(&spec.Source, p.Child("source"))...)

	// Template carries the desired serving config; it never carries a bundle.
	errs = append(errs, validateTemplate(&spec.Template, p.Child("template"))...)

	// LiveRevision, when pinned, names a ServiceRevision. We can't check existence
	// at admission time, but we can reject a malformed name early.
	if spec.LiveRevision != "" {
		for _, msg := range utilvalidation.IsDNS1123Subdomain(spec.LiveRevision) {
			errs = append(errs, field.Invalid(p.Child("liveRevision"), spec.LiveRevision, msg))
		}
	}

	if spec.RevisionHistoryLimit != nil && *spec.RevisionHistoryLimit < 0 {
		errs = append(errs, field.Invalid(p.Child("revisionHistoryLimit"),
			*spec.RevisionHistoryLimit, "must be non-negative"))
	}

	return errs
}

// validateSource enforces the oci-XOR-git union and validates the populated
// variant.
func validateSource(src *ServiceSource, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	switch {
	case src.OCI == nil && src.Git == nil:
		errs = append(errs, field.Required(p, "exactly one of oci (push) or git must be set"))
	case src.OCI != nil && src.Git != nil:
		errs = append(errs, field.Forbidden(p,
			"oci (push) and git are mutually exclusive; set exactly one"))
	}

	// A pushed oci bundle need not be digest-pinned: the controller resolves its tag
	// when minting the revision (minted=false).
	if src.OCI != nil {
		errs = append(errs, validateBundle(src.OCI, p.Child("oci"), false)...)
	}
	if src.Git != nil {
		errs = append(errs, validateGitSource(src.Git, p.Child("git"))...)
	}
	return errs
}

// validateGitSource checks the git/build pipeline of a git-mode Service.
func validateGitSource(g *GitSource, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	if g.URL == "" {
		errs = append(errs, field.Required(p.Child("url"), "git url is required"))
	}
	// Build.Output is the registry the built bundle is pushed to.
	errs = append(errs, validateBundle(&g.Build.Output, p.Child("build").Child("output"), false)...)
	return errs
}

// validateTemplate checks the serving config and the limited metadata a template
// may carry.
func validateTemplate(t *ServiceTemplateSpec, p *field.Path) field.ErrorList {
	errs := validateConfigSpec(&t.Spec, p.Child("spec"))
	errs = append(errs, validateTemplateMeta(&t.ObjectMeta, p.Child("metadata"))...)
	return errs
}

// validateTemplateMeta restricts the template's metadata to the fields meant to
// be propagated onto a minted ServiceRevision: name, generateName, labels, and
// annotations. The inlined ObjectMeta exposes the full identity surface, so the
// namespace (these kinds are cluster-scoped) and the system-owned identity /
// bookkeeping fields are rejected — otherwise a caller could stuff e.g.
// ownerReferences or finalizers that the controller would then copy onto a
// revision.
func validateTemplateMeta(m *metav1.ObjectMeta, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	const forbidden = "must not be set on a template; only name, generateName, labels, and annotations are honored"
	if m.Namespace != "" {
		errs = append(errs, field.Forbidden(p.Child("namespace"), "must not be set; services are cluster-scoped"))
	}
	if m.UID != "" {
		errs = append(errs, field.Forbidden(p.Child("uid"), forbidden))
	}
	if m.ResourceVersion != "" {
		errs = append(errs, field.Forbidden(p.Child("resourceVersion"), forbidden))
	}
	if m.Generation != 0 {
		errs = append(errs, field.Forbidden(p.Child("generation"), forbidden))
	}
	if !m.CreationTimestamp.IsZero() {
		errs = append(errs, field.Forbidden(p.Child("creationTimestamp"), forbidden))
	}
	if m.DeletionTimestamp != nil {
		errs = append(errs, field.Forbidden(p.Child("deletionTimestamp"), forbidden))
	}
	if m.DeletionGracePeriodSeconds != nil {
		errs = append(errs, field.Forbidden(p.Child("deletionGracePeriodSeconds"), forbidden))
	}
	if len(m.OwnerReferences) > 0 {
		errs = append(errs, field.Forbidden(p.Child("ownerReferences"), forbidden))
	}
	if len(m.Finalizers) > 0 {
		errs = append(errs, field.Forbidden(p.Child("finalizers"), forbidden))
	}
	if len(m.ManagedFields) > 0 {
		errs = append(errs, field.Forbidden(p.Child("managedFields"), forbidden))
	}
	return errs
}

// =============================================================================
// ServiceRevision (immutable snapshot)
// =============================================================================

func (r *ServiceRevision) Validate(_ context.Context) field.ErrorList {
	return validateRevisionSpec(&r.Spec, field.NewPath("spec"))
}

func (r *ServiceRevision) ValidateUpdate(ctx context.Context, old runtime.Object) field.ErrorList {
	oldR, ok := old.(*ServiceRevision)
	if !ok {
		return r.Validate(ctx)
	}
	// ServiceRevisions are immutable. Status flows through a separate subresource
	// strategy, so any spec delta reaching here is a forbidden mutation.
	if !apiequality.Semantic.DeepEqual(oldR.Spec, r.Spec) {
		return field.ErrorList{field.Forbidden(field.NewPath("spec"),
			"ServiceRevision spec is immutable")}
	}
	return nil
}

// validateRevisionSpec validates a minted revision: a fully-resolved snapshot
// whose bundle must be present and digest-pinned, plus the serving config.
func validateRevisionSpec(s *ServiceRevisionSpec, p *field.Path) field.ErrorList {
	// A minted revision is digest-addressed and immutable (minted=true).
	errs := validateBundle(&s.Bundle, p.Child("bundle"), true)
	errs = append(errs, validateConfigSpec(&s.ServiceConfigSpec, p)...)
	return errs
}

// =============================================================================
// Shared serving-config validation
// =============================================================================

// validateConfigSpec validates the runtime-mode union, runtime, bindings, and
// env shared by a Service template and a ServiceRevision. p is the path of the
// config block itself (spec for a revision, spec.template.spec for a template).
func validateConfigSpec(s *ServiceConfigSpec, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	// Mode union: at most one of filter/backend.
	if s.Filter != nil && s.Backend != nil {
		errs = append(errs, field.Forbidden(p.Child("backend"),
			"filter and backend are mutually exclusive; set exactly one"))
	}
	if s.Backend != nil {
		errs = append(errs, validateBackend(s.Backend, p.Child("backend"))...)
	}
	if s.Filter != nil {
		errs = append(errs, validateFilter(s.Filter, p.Child("filter"))...)
	}

	// workerd needs a compatibilityDate, but it may come from the built bundle's
	// manifest rather than the spec, so an omitted runtime block is legal. Only
	// flag the likely mistake of providing a runtime block but leaving the date
	// empty.
	if s.Runtime != nil && s.Runtime.CompatibilityDate == "" {
		errs = append(errs, field.Required(p.Child("runtime").Child("compatibilityDate"),
			"compatibilityDate must be set when a runtime block is provided"))
	}

	// Bindings: each is a discriminated union; names must be unique & non-empty.
	seen := map[string]struct{}{}
	for i := range s.Bindings {
		bp := p.Child("bindings").Index(i)
		b := &s.Bindings[i]
		if b.Name == "" {
			errs = append(errs, field.Required(bp.Child("name"), "binding name is required"))
		} else if _, dup := seen[b.Name]; dup {
			errs = append(errs, field.Duplicate(bp.Child("name"), b.Name))
		} else {
			seen[b.Name] = struct{}{}
		}
		errs = append(errs, validateBinding(b, bp)...)
	}

	// Egress: an absent block and an empty one both mean "the default
	// gateway", so nothing is required. disabled is the hard opt-out and
	// contradicts naming a gateway. Ref existence is checked by the control
	// plane (EgressReady condition), not at admission — cf. liveRevision.
	if e := s.Egress; e != nil {
		if e.Disabled && e.GatewayRef != "" {
			errs = append(errs, field.Forbidden(p.Child("egress").Child("gatewayRef"),
				"disabled and gatewayRef are mutually exclusive"))
		}
		if e.GatewayRef != "" {
			for _, msg := range utilvalidation.IsDNS1123Subdomain(string(e.GatewayRef)) {
				errs = append(errs, field.Invalid(p.Child("egress").Child("gatewayRef"), e.GatewayRef, msg))
			}
		}
	}

	// Env: names must be unique & non-empty.
	envSeen := map[string]struct{}{}
	for i := range s.Env {
		ep := p.Child("env").Index(i)
		name := s.Env[i].Name
		if name == "" {
			errs = append(errs, field.Required(ep.Child("name"), "env name is required"))
			continue
		}
		if _, dup := envSeen[name]; dup {
			errs = append(errs, field.Duplicate(ep.Child("name"), name))
		}
		envSeen[name] = struct{}{}
	}

	return errs
}

// validateBundle checks an OCI bundle reference. minted requires a concrete
// digest (a stored ServiceRevision is digest-addressed and immutable).
func validateBundle(b *BundleRef, p *field.Path, minted bool) field.ErrorList {
	errs := field.ErrorList{}
	if b.Repo == "" {
		errs = append(errs, field.Required(p.Child("repo"), "bundle repo is required"))
	}
	if b.Credentials != nil && b.CredentialsRef != nil {
		errs = append(errs, field.Forbidden(p.Child("credentialsRef"),
			"credentials and credentialsRef are mutually exclusive"))
	} else if b.CredentialsRef != nil {
		// Reject at admission what the data plane cannot honor: the bundle
		// fetcher has no secret store to resolve a ref against yet, and letting
		// the object through would only surface later as per-request 502s with
		// no signal on the object.
		errs = append(errs, field.Forbidden(p.Child("credentialsRef"),
			"credentialsRef is not supported yet; use inline credentials"))
	}
	if minted && b.Digest == "" {
		errs = append(errs, field.Required(p.Child("digest"),
			"a minted ServiceRevision bundle must be pinned to a concrete digest"))
	}
	return errs
}

func validateBackend(b *BackendConfig, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	switch b.Protocol {
	case "", HTTP1, HTTP2:
		// L7: served via Envoy; the listen port is an internal Envoy<->runtime
		// contract programmed by the controller, not a user knob.
		if b.Port != nil {
			errs = append(errs, field.Forbidden(p.Child("port"),
				"port is not configurable for http1/http2 backends (the listen port is programmed by the controller)"))
		}
	case TCP, UDP:
		// L4: the service is a raw listener, so the port IS the contract.
		if b.Port == nil {
			errs = append(errs, field.Required(p.Child("port"),
				"port is required for tcp/udp backends"))
		}
	default:
		errs = append(errs, field.NotSupported(p.Child("protocol"), b.Protocol,
			[]string{string(HTTP1), string(HTTP2), string(TCP), string(UDP)}))
	}
	if b.Port != nil && (*b.Port < 1 || *b.Port > 65535) {
		errs = append(errs, field.Invalid(p.Child("port"), *b.Port, "must be in [1,65535]"))
	}
	return errs
}

func validateFilter(f *FilterConfig, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	switch f.Phase {
	case "", RequestPhase, ResponsePhase, BothPhases:
	default:
		errs = append(errs, field.NotSupported(p.Child("phase"), f.Phase,
			[]string{string(RequestPhase), string(ResponsePhase), string(BothPhases)}))
	}
	switch f.FailureMode {
	case "", FailOpen, FailClosed:
	default:
		errs = append(errs, field.NotSupported(p.Child("failureMode"), f.FailureMode,
			[]string{string(FailOpen), string(FailClosed)}))
	}
	return errs
}

func validateBinding(b *Binding, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}

	// Exactly one variant block, and it must match the declared type.
	set := 0
	if b.Secret != nil {
		set++
	}
	if b.KV != nil {
		set++
	}
	if b.Service != nil {
		set++
	}
	if set > 1 {
		errs = append(errs, field.Forbidden(p, "exactly one of secret/kv/service may be set"))
	}

	switch b.Type {
	case SecretBindingType:
		if b.Secret == nil {
			errs = append(errs, field.Required(p.Child("secret"), "secret is required when type=secret"))
		} else {
			if b.Secret.Store == "" {
				errs = append(errs, field.Required(p.Child("secret", "store"), "store must name a SecretStore"))
			}
			if b.Secret.Key == "" {
				errs = append(errs, field.Required(p.Child("secret", "key"), "key within the store is required"))
			}
		}
	case KVBindingType:
		if b.KV == nil {
			errs = append(errs, field.Required(p.Child("kv"), "kv is required when type=kv"))
		}
	case ServiceBindingType:
		if b.Service == nil {
			errs = append(errs, field.Required(p.Child("service"), "service is required when type=service"))
		}
	default:
		errs = append(errs, field.NotSupported(p.Child("type"), b.Type,
			[]string{string(SecretBindingType), string(KVBindingType), string(ServiceBindingType)}))
	}

	if b.Secret != nil && b.Type != SecretBindingType {
		errs = append(errs, field.Forbidden(p.Child("secret"), "secret set but type is not 'secret'"))
	}
	if b.KV != nil && b.Type != KVBindingType {
		errs = append(errs, field.Forbidden(p.Child("kv"), "kv set but type is not 'kv'"))
	}
	if b.Service != nil && b.Type != ServiceBindingType {
		errs = append(errs, field.Forbidden(p.Child("service"), "service set but type is not 'service'"))
	}
	return errs
}

// =============================================================================
// Build (immutable build record)
// =============================================================================

func (b *Build) Validate(_ context.Context) field.ErrorList {
	return validateBuildSpec(&b.Spec, field.NewPath("spec"))
}

func (b *Build) ValidateUpdate(ctx context.Context, old runtime.Object) field.ErrorList {
	oldB, ok := old.(*Build)
	if !ok {
		return b.Validate(ctx)
	}
	// BuildSpec is the immutable input of one build attempt.
	if !apiequality.Semantic.DeepEqual(oldB.Spec, b.Spec) {
		return field.ErrorList{field.Forbidden(field.NewPath("spec"),
			"Build spec is immutable")}
	}
	return nil
}

func validateBuildSpec(s *BuildSpec, p *field.Path) field.ErrorList {
	errs := field.ErrorList{}
	if s.ServiceRef == "" {
		errs = append(errs, field.Required(p.Child("serviceRef"), "serviceRef is required"))
	}
	if s.Commit == "" {
		errs = append(errs, field.Required(p.Child("commit"), "commit is required"))
	}
	if s.Ref == "" {
		errs = append(errs, field.Required(p.Child("ref"), "ref is required"))
	}
	return errs
}
