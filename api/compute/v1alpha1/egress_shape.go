package v1alpha1

import "fmt"

// EgressListenerShape is the on-the-wire shape of a listener: how the
// sandbox-side dialer treats connections it steers to that listener's
// backend. It is the value carried in the compiled config
// (apoxy.workerd.v1.BackendListener.shape). Ported from clrk's
// clrk.apoxy.dev/v1alpha1 so agents and compute share one shape vocabulary.
type EgressListenerShape string

const (
	EgressShapeHTTP           EgressListenerShape = "http"
	EgressShapeHTTPS          EgressListenerShape = "https"
	EgressShapeTLSTerminate   EgressListenerShape = "tls-terminate"
	EgressShapeTLSPassthrough EgressListenerShape = "tls-passthrough"
	EgressShapeTCP            EgressListenerShape = "tcp"
)

// ShapeForListener resolves an EgressListener to its on-the-wire shape.
// Returns ("", error) for unsupported combinations — callers surface the
// error on Status.Conditions[Ready] instead of compiling the listener.
func ShapeForListener(l EgressListener) (EgressListenerShape, error) {
	switch l.Protocol {
	case EgressProtocolHTTP:
		return EgressShapeHTTP, nil
	case EgressProtocolHTTPS:
		return EgressShapeHTTPS, nil
	case EgressProtocolTLS:
		mode := EgressTLSPassthrough
		if l.TLS != nil && l.TLS.Mode != "" {
			mode = l.TLS.Mode
		}
		switch mode {
		case EgressTLSTerminate:
			return EgressShapeTLSTerminate, nil
		case EgressTLSPassthrough:
			return EgressShapeTLSPassthrough, nil
		default:
			return "", fmt.Errorf("listener %q: invalid TLS mode %q", l.Name, mode)
		}
	case EgressProtocolTCP:
		return EgressShapeTCP, nil
	default:
		return "", fmt.Errorf("listener %q: unknown protocol %q", l.Name, l.Protocol)
	}
}

// ShapePriority orders listener shapes for tie-breaking at dial time when
// multiple listeners catch the same destination port. Higher value wins.
// TLS-terminate / HTTPS go first because they sniff and can carry any byte
// stream; plain TCP is last-resort because it hard-commits the connection
// to passthrough.
func ShapePriority(s EgressListenerShape) int {
	switch s {
	case EgressShapeTLSTerminate:
		return 5
	case EgressShapeHTTPS:
		return 4
	case EgressShapeHTTP:
		return 3
	case EgressShapeTLSPassthrough:
		return 2
	case EgressShapeTCP:
		return 1
	default:
		return 0
	}
}
