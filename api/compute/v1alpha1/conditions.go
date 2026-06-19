package v1alpha1

// Condition types for the compute control plane (the Service minting reconciler,
// APO-796). The data plane (the workerd resident reconciler) is READ-ONLY on these
// objects — it reports per-node readiness over the private publish channel, never
// by writing a condition — so there is no data-plane-written condition here.
const (
	// ConditionAccepted (on Service) reports that the Service spec is valid and a
	// ServiceRevision has been minted from spec.template + spec.source.
	ConditionAccepted = "Accepted"
	// ConditionReady (on Service) reports that the Service's intended revision is
	// being served. Which revision each backplane actually serves is a per-node
	// decision the workerd-manager reports over the private publish channel, so
	// this is a control-plane summary and is never written by the data plane.
	ConditionReady = "Ready"
)
