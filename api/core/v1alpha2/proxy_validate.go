package v1alpha2

import (
	"context"
	"net/url"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/apoxy-dev/apoxy/api/resource/resourcestrategy"
)

// envoyVersionRe matches an Envoy release tag such as "v1.35.13". The
// leading "v" is optional.
var envoyVersionRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

var _ resourcestrategy.Defaulter = &Proxy{}

// Default sets the default values for a Proxy.
func (r *Proxy) Default() {
	if r.Spec.Shutdown == nil {
		r.Spec.Shutdown = &ShutdownConfig{}
	}
	if r.Spec.Shutdown.DrainTimeout == nil {
		r.Spec.Shutdown.DrainTimeout = &metav1.Duration{Duration: DefaultDrainTimeout}
	}
	if r.Spec.Shutdown.MinimumDrainTime == nil {
		r.Spec.Shutdown.MinimumDrainTime = &metav1.Duration{Duration: DefaultDrainTimeout}
	}
}

var _ resourcestrategy.Validater = &Proxy{}
var _ resourcestrategy.ValidateUpdater = &Proxy{}

// isCloudProvider returns true if the proxy uses the cloud infrastructure provider.
func isCloudProvider(p InfraProvider) bool {
	return p == InfraProviderCloud || p == ""
}

func (r *Proxy) validate() field.ErrorList {
	errs := field.ErrorList{}
	spec := r.Spec

	if spec.Shutdown.MinimumDrainTime.Duration > spec.Shutdown.DrainTimeout.Duration {
		errs = append(errs,
			field.Forbidden(
				field.NewPath("spec", "shutdown", "minimumDrainTime"),
				"minimumDrainTime must be less than or equal to drainTimeout"))
	}

	// Telemetry settings are managed by CloudMonitoringIntegration for cloud proxies.
	if isCloudProvider(spec.Provider) && spec.Telemetry != nil {
		telPath := field.NewPath("spec", "telemetry")
		msg := "telemetry settings are not configurable for cloud proxies; use CloudMonitoringIntegration instead"
		if spec.Telemetry.AccessLogs != nil {
			errs = append(errs, field.Forbidden(telPath.Child("accessLogs"), msg))
		}
		if spec.Telemetry.ContentLogs != nil {
			errs = append(errs, field.Forbidden(telPath.Child("contentLogs"), msg))
		}
		if spec.Telemetry.Tracing != nil {
			errs = append(errs, field.Forbidden(telPath.Child("tracing"), msg))
		}
		if spec.Telemetry.OtelCollectorConfig != nil {
			errs = append(errs, field.Forbidden(telPath.Child("otelCollectorConfig"), msg))
		}
		if spec.Telemetry.ThirdPartySinks != nil {
			errs = append(errs, field.Forbidden(telPath.Child("thirdPartySinks"), msg))
		}
	}

	if spec.Envoy != nil {
		envoyPath := field.NewPath("spec", "envoy")
		// The Envoy binary of a cloud proxy is chosen by the platform.
		if isCloudProvider(spec.Provider) {
			errs = append(errs, field.Forbidden(envoyPath, "envoy settings are not configurable for cloud proxies"))
		}
		if v := spec.Envoy.Version; v != "" && !envoyVersionRe.MatchString(v) {
			errs = append(errs, field.Invalid(envoyPath.Child("version"), v,
				"must be a release tag such as v1.35.13"))
		}
		if u := spec.Envoy.ReleaseURL; u != "" {
			parsed, err := url.Parse(u)
			if err != nil {
				errs = append(errs, field.Invalid(envoyPath.Child("releaseURL"), u, "must be a valid URL"))
			} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
				errs = append(errs, field.Invalid(envoyPath.Child("releaseURL"), u, "must be an http or https URL"))
			} else if parsed.Host == "" {
				errs = append(errs, field.Invalid(envoyPath.Child("releaseURL"), u, "must have a host"))
			}
		}
	}

	return errs
}

func (r *Proxy) Validate(ctx context.Context) field.ErrorList {
	return r.validate()
}

func (r *Proxy) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	p := obj.(*Proxy)
	return p.validate()
}
