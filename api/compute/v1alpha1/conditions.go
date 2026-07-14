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
	// ConditionEgressReady (on Service) reports that the service's egress
	// config resolves: the selected EgressGateway exists (or is the implicit
	// built-in "default"), is Ready, and the compiled egress config has been
	// dispatched to the data plane. Reasons: Applied, GatewayNotFound,
	// GatewayNotReady, Disabled. GatewayNotFound can only fire for an
	// explicit ref to a name other than "default" — the "default" name always
	// resolves, to the built-in allow-all gateway when no object exists (see
	// DefaultEgressGatewayName). Control-plane-written only, per this file's
	// contract.
	ConditionEgressReady = "EgressReady"
)
