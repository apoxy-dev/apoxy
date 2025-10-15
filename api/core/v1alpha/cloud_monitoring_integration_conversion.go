package v1alpha

import (
	v1alpha2 "github.com/apoxy-dev/apoxy/api/core/v1alpha2"
)

// convertCloudMonitoringIntegrationSpecFromV1Alpha1ToV1Alpha2 converts a v1alpha CloudMonitoringIntegrationSpec to v1alpha2
func convertCloudMonitoringIntegrationSpecFromV1Alpha1ToV1Alpha2(in *CloudMonitoringIntegrationSpec) *v1alpha2.CloudMonitoringIntegrationSpec {
	if in == nil {
		return nil
	}

	return &v1alpha2.CloudMonitoringIntegrationSpec{
		Enabled:            in.Enabled,
		DatadogCredentials: convertDatadogCredentialsFromV1Alpha1ToV1Alpha2(in.DatadogCredentials),
		GrafanaCredentials: convertGrafanaCredentialsFromV1Alpha1ToV1Alpha2(in.GrafanaCredentials),
		AxiomCredentials:   convertAxiomCredentialsFromV1Alpha1ToV1Alpha2(in.AxiomCredentials),
	}
}

// convertCloudMonitoringIntegrationSpecFromV1Alpha2ToV1Alpha1 converts a v1alpha2 CloudMonitoringIntegrationSpec to v1alpha
func convertCloudMonitoringIntegrationSpecFromV1Alpha2ToV1Alpha1(in *v1alpha2.CloudMonitoringIntegrationSpec) *CloudMonitoringIntegrationSpec {
	if in == nil {
		return nil
	}

	return &CloudMonitoringIntegrationSpec{
		Enabled:            in.Enabled,
		DatadogCredentials: convertDatadogCredentialsFromV1Alpha2ToV1Alpha1(in.DatadogCredentials),
		GrafanaCredentials: convertGrafanaCredentialsFromV1Alpha2ToV1Alpha1(in.GrafanaCredentials),
		AxiomCredentials:   convertAxiomCredentialsFromV1Alpha2ToV1Alpha1(in.AxiomCredentials),
	}
}

// convertDatadogCredentialsFromV1Alpha1ToV1Alpha2 converts v1alpha DatadogCredentials to v1alpha2
func convertDatadogCredentialsFromV1Alpha1ToV1Alpha2(in *DatadogCredentials) *v1alpha2.DatadogCredentials {
	if in == nil {
		return nil
	}

	return &v1alpha2.DatadogCredentials{
		APIKey: in.APIKey,
		Site:   in.Site,
	}
}

// convertDatadogCredentialsFromV1Alpha2ToV1Alpha1 converts v1alpha2 DatadogCredentials to v1alpha
func convertDatadogCredentialsFromV1Alpha2ToV1Alpha1(in *v1alpha2.DatadogCredentials) *DatadogCredentials {
	if in == nil {
		return nil
	}

	return &DatadogCredentials{
		APIKey: in.APIKey,
		Site:   in.Site,
	}
}

// convertGrafanaCredentialsFromV1Alpha1ToV1Alpha2 converts v1alpha GrafanaCredentials to v1alpha2
func convertGrafanaCredentialsFromV1Alpha1ToV1Alpha2(in *GrafanaCredentials) *v1alpha2.GrafanaCredentials {
	if in == nil {
		return nil
	}

	return &v1alpha2.GrafanaCredentials{
		APIKey:     in.APIKey,
		InstanceID: in.InstanceID,
		Endpoint:   in.Endpoint,
	}
}

// convertGrafanaCredentialsFromV1Alpha2ToV1Alpha1 converts v1alpha2 GrafanaCredentials to v1alpha
func convertGrafanaCredentialsFromV1Alpha2ToV1Alpha1(in *v1alpha2.GrafanaCredentials) *GrafanaCredentials {
	if in == nil {
		return nil
	}

	return &GrafanaCredentials{
		APIKey:     in.APIKey,
		InstanceID: in.InstanceID,
		Endpoint:   in.Endpoint,
	}
}

// convertAxiomCredentialsFromV1Alpha1ToV1Alpha2 converts v1alpha AxiomCredentials to v1alpha2
func convertAxiomCredentialsFromV1Alpha1ToV1Alpha2(in *AxiomCredentials) *v1alpha2.AxiomCredentials {
	if in == nil {
		return nil
	}

	return &v1alpha2.AxiomCredentials{
		APIToken:    in.APIToken,
		Region:      in.Region,
		DatasetName: in.DatasetName,
	}
}

// convertAxiomCredentialsFromV1Alpha2ToV1Alpha1 converts v1alpha2 AxiomCredentials to v1alpha
func convertAxiomCredentialsFromV1Alpha2ToV1Alpha1(in *v1alpha2.AxiomCredentials) *AxiomCredentials {
	if in == nil {
		return nil
	}

	return &AxiomCredentials{
		APIToken:    in.APIToken,
		Region:      in.Region,
		DatasetName: in.DatasetName,
	}
}

// convertCloudMonitoringIntegrationStatusFromV1Alpha1ToV1Alpha2 converts a v1alpha CloudMonitoringIntegrationStatus to v1alpha2
func convertCloudMonitoringIntegrationStatusFromV1Alpha1ToV1Alpha2(in *CloudMonitoringIntegrationStatus) *v1alpha2.CloudMonitoringIntegrationStatus {
	if in == nil {
		return nil
	}

	return &v1alpha2.CloudMonitoringIntegrationStatus{
		Conditions:         in.Conditions,
		LastSyncTime:       in.LastSyncTime,
		ObservedGeneration: in.ObservedGeneration,
	}
}

// convertCloudMonitoringIntegrationStatusFromV1Alpha2ToV1Alpha1 converts a v1alpha2 CloudMonitoringIntegrationStatus to v1alpha
func convertCloudMonitoringIntegrationStatusFromV1Alpha2ToV1Alpha1(in *v1alpha2.CloudMonitoringIntegrationStatus) *CloudMonitoringIntegrationStatus {
	if in == nil {
		return nil
	}

	return &CloudMonitoringIntegrationStatus{
		Conditions:         in.Conditions,
		LastSyncTime:       in.LastSyncTime,
		ObservedGeneration: in.ObservedGeneration,
	}
}
