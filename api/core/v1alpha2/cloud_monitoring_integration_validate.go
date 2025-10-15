package v1alpha2

import (
	"context"

	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/resource/resourcestrategy"
)

var (
	_ resourcestrategy.Validater       = &CloudMonitoringIntegration{}
	_ resourcestrategy.ValidateUpdater = &CloudMonitoringIntegration{}
)

func (c *CloudMonitoringIntegration) Validate(ctx context.Context) field.ErrorList {
	return c.validate()
}

func (c *CloudMonitoringIntegration) ValidateUpdate(ctx context.Context, obj runtime.Object) field.ErrorList {
	cmi := &CloudMonitoringIntegration{}
	// XXX: Conversion needs to happen in apiserver-runtime before validation hooks are called.
	if mv, ok := obj.(resource.MultiVersionObject); ok {
		mv.ConvertToStorageVersion(cmi)
	} else if cmi, ok = obj.(*CloudMonitoringIntegration); !ok {
		return field.ErrorList{
			field.Invalid(field.NewPath("kind"), obj.GetObjectKind().GroupVersionKind().Kind, "expected CloudMonitoringIntegration"),
		}
	}

	return cmi.validate()
}

// validate performs validation of the CloudMonitoringIntegration.
func (c *CloudMonitoringIntegration) validate() field.ErrorList {
	var allErrs field.ErrorList
	specPath := field.NewPath("spec")

	// Count how many credential types are specified
	credentialCount := 0
	if c.Spec.DatadogCredentials != nil {
		credentialCount++
	}
	if c.Spec.GrafanaCredentials != nil {
		credentialCount++
	}
	if c.Spec.AxiomCredentials != nil {
		credentialCount++
	}

	if credentialCount == 0 {
		allErrs = append(allErrs, field.Required(specPath,
			"must specify one of: datadogCredentials, grafanaCredentials, or axiomCredentials"))
	} else if credentialCount > 1 {
		allErrs = append(allErrs, field.Invalid(specPath, credentialCount,
			"must specify only one of: datadogCredentials, grafanaCredentials, or axiomCredentials"))
	}

	if c.Spec.DatadogCredentials != nil {
		allErrs = append(allErrs, validateDatadogCredentials(c.Spec.DatadogCredentials, specPath.Child("datadogCredentials"))...)
	}

	if c.Spec.GrafanaCredentials != nil {
		allErrs = append(allErrs, validateGrafanaCredentials(c.Spec.GrafanaCredentials, specPath.Child("grafanaCredentials"))...)
	}

	if c.Spec.AxiomCredentials != nil {
		allErrs = append(allErrs, validateAxiomCredentials(c.Spec.AxiomCredentials, specPath.Child("axiomCredentials"))...)
	}

	return allErrs
}

func validateDatadogCredentials(creds *DatadogCredentials, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if creds.APIKey == "" {
		allErrs = append(allErrs, field.Required(fldPath,
			"must specify apiKey"))
	}

	return allErrs
}

func validateGrafanaCredentials(creds *GrafanaCredentials, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if creds.APIKey == "" {
		allErrs = append(allErrs, field.Required(fldPath,
			"must specify apiKey"))
	}

	return allErrs
}

func validateAxiomCredentials(creds *AxiomCredentials, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if creds.APIToken == "" {
		allErrs = append(allErrs, field.Required(fldPath,
			"must specify apiToken"))
	}

	return allErrs
}
