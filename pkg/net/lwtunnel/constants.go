package lwtunnel

const (
	// DefaultGeneveMTU is the MTU for Geneve tunnel interfaces. Must be >=
	// the tunnel TUN MTU (1420) so that overlay packets are not fragmented
	// on the Geneve leg. Safe to set high since Geneve runs over VPC
	// networks that support jumbo frames.
	DefaultGeneveMTU = 1450
)
