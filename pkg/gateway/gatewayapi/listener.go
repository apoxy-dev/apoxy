// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
	"github.com/apoxy-dev/apoxy/pkg/log"
)

var _ ListenersTranslator = (*Translator)(nil)

type ListenersTranslator interface {
	ProcessListeners(gateways []*GatewayContext, xdsIR XdsIRMap, resources *Resources)
}

func (t *Translator) ProcessListeners(gateways []*GatewayContext, xdsIR XdsIRMap, resources *Resources) {
	t.validateConflictedLayer7Listeners(gateways)
	t.validateConflictedLayer4Listeners(gateways, gwapiv1.TCPProtocolType, gwapiv1.TLSProtocolType)
	t.validateConflictedLayer4Listeners(gateways, gwapiv1.UDPProtocolType)

	// Iterate through all listeners to validate spec
	// and compute status for each, and add valid ones
	// to the Xds IR.
	for _, gateway := range gateways {
		log.Infof("Processing listeners for Gateway %s", gateway.Gateway.Name)
		irKey := t.getIRKey(gateway.Gateway)

		// TODO(dsky): Merge config from Proxy object here.
		xdsIR[irKey].Tracing = t.processTracing(gateway.Gateway, resources.Proxies)
		//xdsIR[irKey].AccessLog = processAccessLog(infraIR[irKey].Proxy.Config)
		//xdsIR[irKey].Metrics = processMetrics(infraIR[irKey].Proxy.Config)

		for _, listener := range gateway.listeners {
			// Process protocol & supported kinds
			switch listener.Protocol {
			case gwapiv1.TLSProtocolType:
				if listener.TLS != nil && listener.TLS.Mode != nil {
					switch *listener.TLS.Mode {
					case gwapiv1.TLSModePassthrough:
						t.validateAllowedRoutes(listener, KindTLSRoute)
					case gwapiv1.TLSModeTerminate:
						t.validateAllowedRoutes(listener, KindTCPRoute, KindTLSRoute)
					default:
						t.validateAllowedRoutes(listener, KindTCPRoute, KindTLSRoute)
					}
				} else {
					t.validateAllowedRoutes(listener, KindTCPRoute, KindTLSRoute)
				}
			case gwapiv1.HTTPProtocolType, gwapiv1.HTTPSProtocolType:
				t.validateAllowedRoutes(listener, KindHTTPRoute, KindGRPCRoute)
			case gwapiv1.TCPProtocolType:
				t.validateAllowedRoutes(listener, KindTCPRoute)
			case gwapiv1.UDPProtocolType:
				t.validateAllowedRoutes(listener, KindUDPRoute)
			default:
				listener.SetCondition(
					gwapiv1.ListenerConditionAccepted,
					metav1.ConditionFalse,
					gwapiv1.ListenerReasonUnsupportedProtocol,
					fmt.Sprintf("Protocol %s is unsupported, must be %s, %s, %s or %s.", listener.Protocol,
						gwapiv1.HTTPProtocolType, gwapiv1.HTTPSProtocolType, gwapiv1.TCPProtocolType, gwapiv1.UDPProtocolType),
				)
			}

			// Validate allowed namespaces
			t.validateAllowedNamespaces(listener)

			// Process TLS configuration
			t.validateTLSConfiguration(listener, resources)

			// Process Hostname configuration
			t.validateHostName(listener)

			// Process conditions and check if the listener is ready
			isReady, msg := t.validateListenerConditions(listener)
			if !isReady {
				log.Warnf("Listener %s is not ready: %v", listener.Name, msg)
				continue
			}

			log.Infof("Adding listener %s to IR", listener.Name)

			// Add the listener to the Xds IR
			servicePort := &protocolPort{protocol: listener.Protocol, port: int32(listener.Port)}
			containerPort := servicePortToContainerPort(servicePort.port)
			switch listener.Protocol {
			case gwapiv1.HTTPProtocolType, gwapiv1.HTTPSProtocolType:
				log.Infof("Adding HTTP listener %s to IR", listener.Name)
				irListener := &ir.HTTPListener{
					CoreListenerDetails: ir.CoreListenerDetails{
						Name:    irListenerName(listener),
						Address: "0.0.0.0",
						Port:    uint32(containerPort),
					},
					TLS: irTLSConfigs(listener),
					Path: ir.PathSettings{
						MergeSlashes:         true,
						EscapedSlashesAction: ir.UnescapeAndRedirect,
					},
					EdgeFunctionRevisions: resources.EdgeFunctionRevisions,
				}
				if listener.Hostname != nil {
					irListener.Hostnames = append(irListener.Hostnames, string(*listener.Hostname))
				} else {
					// Hostname specifies the virtual hostname to match for protocol types that define this concept.
					// When unspecified, all hostnames are matched. This field is ignored for protocols that don't require hostname based matching.
					// see more https://gateway-api.sigs.k8s.io/references/spec/#gateway.networking.k8s.io/gwapiv1.Listener.
					irListener.Hostnames = append(irListener.Hostnames, "*")
				}
				xdsIR[irKey].HTTP = append(xdsIR[irKey].HTTP, irListener)
			case gwapiv1.TCPProtocolType, gwapiv1.TLSProtocolType:
				log.Infof("Adding TCP listener %s to IR", listener.Name)
				irListener := &ir.TCPListener{
					CoreListenerDetails: ir.CoreListenerDetails{
						Name:    irListenerName(listener),
						Address: "0.0.0.0",
						Port:    uint32(containerPort),
					},
					TLS: irTLSConfigsForTCPListener(listener),
				}
				xdsIR[irKey].TCP = append(xdsIR[irKey].TCP, irListener)
			}
		}
	}
}
