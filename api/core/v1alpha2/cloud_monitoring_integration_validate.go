package v1alpha2

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateCreate validates the CloudMonitoringIntegration on creation.
func (c *CloudMonitoringIntegration) ValidateCreate() field.ErrorList {
	return c.validate()
}

// ValidateUpdate validates the CloudMonitoringIntegration on update.
func (c *CloudMonitoringIntegration) ValidateUpdate(old *CloudMonitoringIntegration) field.ErrorList {
	return c.validate()
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

	// Exactly one credential type must be specified
	if credentialCount == 0 {
		allErrs = append(allErrs, field.Required(specPath,
			"must specify one of: datadogCredentials, grafanaCredentials, or axiomCredentials"))
	} else if credentialCount > 1 {
		allErrs = append(allErrs, field.Invalid(specPath, credentialCount,
			"must specify only one of: datadogCredentials, grafanaCredentials, or axiomCredentials"))
	}

	// Validate DataDog credentials if present
	if c.Spec.DatadogCredentials != nil {
		allErrs = append(allErrs, validateDatadogCredentials(c.Spec.DatadogCredentials, specPath.Child("datadogCredentials"))...)
	}

	// Validate Grafana credentials if present
	if c.Spec.GrafanaCredentials != nil {
		allErrs = append(allErrs, validateGrafanaCredentials(c.Spec.GrafanaCredentials, specPath.Child("grafanaCredentials"))...)
	}

	// Validate Axiom credentials if present
	if c.Spec.AxiomCredentials != nil {
		allErrs = append(allErrs, validateAxiomCredentials(c.Spec.AxiomCredentials, specPath.Child("axiomCredentials"))...)
	}

	return allErrs
}

func validateDatadogCredentials(creds *DatadogCredentials, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// APIKey must be specified
	if creds.APIKey == "" {
		allErrs = append(allErrs, field.Required(fldPath,
			"must specify apiKey"))
	}

	return allErrs
}

func validateGrafanaCredentials(creds *GrafanaCredentials, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// APIKey must be specified
	if creds.APIKey == "" {
		allErrs = append(allErrs, field.Required(fldPath,
			"must specify apiKey"))
	}

	return allErrs
}

func validateAxiomCredentials(creds *AxiomCredentials, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// APIToken must be specified
	if creds.APIToken == "" {
		allErrs = append(allErrs, field.Required(fldPath,
			"must specify apiToken"))
	}

	return allErrs
}

// ValidateDelete validates the CloudMonitoringIntegration on deletion.
func (c *CloudMonitoringIntegration) ValidateDelete() field.ErrorList {
	return nil
}

// Validate implements the validation interface.
func (c *CloudMonitoringIntegration) Validate() error {
	if errs := c.validate(); len(errs) > 0 {
		return fmt.Errorf("validation failed: %v", errs)
	}
	return nil
}
