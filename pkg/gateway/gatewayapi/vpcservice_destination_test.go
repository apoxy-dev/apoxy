package gatewayapi

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	vpcv1alpha1 "github.com/apoxy-dev/apoxy/api/vpc/v1alpha1"
	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
)

func vpcService(name, hostname, network, appProtocol string) *vpcv1alpha1.VPCService {
	return &vpcv1alpha1.VPCService{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: vpcv1alpha1.VPCServiceSpec{
			NetworkRef:  vpcv1alpha1.VPCNetworkRef{Name: network},
			Hostname:    hostname,
			AppProtocol: appProtocol,
		},
	}
}

// TestProcessVPCServiceDestinationSetting pins the contract of a direct
// VPCService backendRef: the destination is the service's vpc-zone FQDN
// (input-derived, so the cloud xDS patch layer rewrites it to overlay EDS),
// the port comes from the backendRef, and the upstream protocol comes from
// spec.appProtocol.
func TestProcessVPCServiceDestinationSetting(t *testing.T) {
	cases := []struct {
		name         string
		svc          *vpcv1alpha1.VPCService
		refName      string
		port         *gwapiv1.PortNumber
		protocol     ir.AppProtocol
		wantErr      bool
		wantHost     string
		wantPort     uint32
		wantProtocol ir.AppProtocol
	}{
		{
			name:         "hostname defaults to object name",
			svc:          vpcService("private-api", "", "default", ""),
			refName:      "private-api",
			port:         ptr.To(gwapiv1.PortNumber(8080)),
			protocol:     ir.HTTP,
			wantHost:     "private-api.default.vpc.apoxy.net",
			wantPort:     8080,
			wantProtocol: ir.HTTP,
		},
		{
			name:         "explicit hostname and network",
			svc:          vpcService("svc-obj", "api", "prod-net", ""),
			refName:      "svc-obj",
			port:         ptr.To(gwapiv1.PortNumber(9000)),
			protocol:     ir.HTTP,
			wantHost:     "api.prod-net.vpc.apoxy.net",
			wantPort:     9000,
			wantProtocol: ir.HTTP,
		},
		{
			name:         "h2c app protocol",
			svc:          vpcService("grpcish", "", "default", vpcv1alpha1.AppProtocolH2C),
			refName:      "grpcish",
			port:         ptr.To(gwapiv1.PortNumber(50051)),
			protocol:     ir.HTTP,
			wantHost:     "grpcish.default.vpc.apoxy.net",
			wantPort:     50051,
			wantProtocol: ir.HTTP2,
		},
		{
			name:         "grpc app protocol",
			svc:          vpcService("greeter", "", "default", vpcv1alpha1.AppProtocolGRPC),
			refName:      "greeter",
			port:         ptr.To(gwapiv1.PortNumber(50051)),
			protocol:     ir.HTTP,
			wantHost:     "greeter.default.vpc.apoxy.net",
			wantPort:     50051,
			wantProtocol: ir.GRPC,
		},
		{
			name:    "missing port",
			svc:     vpcService("private-api", "", "default", ""),
			refName: "private-api",
			wantErr: true,
		},
		{
			name:    "service not found",
			svc:     vpcService("private-api", "", "default", ""),
			refName: "no-such-service",
			port:    ptr.To(gwapiv1.PortNumber(8080)),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Translator{}
			resources := &Resources{VPCServices: []*vpcv1alpha1.VPCService{tc.svc}}
			ds, err := tr.processVPCServiceDestinationSetting(gwapiv1.BackendObjectReference{
				Name: gwapiv1.ObjectName(tc.refName),
				Port: tc.port,
			}, tc.protocol, resources)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got destination %+v", ds)
				}
				return
			}
			if err != nil {
				t.Fatalf("processVPCServiceDestinationSetting: %v", err)
			}
			if !ds.InputDerived {
				t.Fatalf("vpc destination setting is not input-derived")
			}
			if ds.AddressType == nil || *ds.AddressType != ir.FQDN {
				t.Fatalf("address type = %v, want FQDN", ds.AddressType)
			}
			if ds.Protocol != tc.wantProtocol {
				t.Fatalf("protocol = %v, want %v", ds.Protocol, tc.wantProtocol)
			}
			if len(ds.Endpoints) != 1 {
				t.Fatalf("endpoints = %d, want 1", len(ds.Endpoints))
			}
			if ds.Endpoints[0].Host != tc.wantHost || ds.Endpoints[0].Port != tc.wantPort {
				t.Fatalf("endpoint = %s:%d, want %s:%d",
					ds.Endpoints[0].Host, ds.Endpoints[0].Port, tc.wantHost, tc.wantPort)
			}
		})
	}
}
