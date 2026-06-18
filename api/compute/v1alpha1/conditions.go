package v1alpha1

// Condition types shared by the compute control plane (the Service minting
// reconciler) and data plane (the workerd resident reconciler, APO-796).
const (
	// ConditionAccepted (on Service) reports that the Service spec is valid and a
	// ServiceRevision has been minted from spec.template + spec.source.
	ConditionAccepted = "Accepted"
	// ConditionReady (on Service) reports that the live revision is resident and
	// serving (its ResidentReady condition is true).
	ConditionReady = "Ready"
	// ConditionResidentReady (on ServiceRevision) reports that the workerd
	// resident has loaded this revision's isolate and it is accepting requests.
	// It is written by the resident reconciler (the ServiceManager data plane).
	ConditionResidentReady = "ResidentReady"
)
