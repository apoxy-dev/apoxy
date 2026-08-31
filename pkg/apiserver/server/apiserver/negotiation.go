package apiserver

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// WithJSONAndYAML returns ns advertising only the media types the apoxy API
// types actually support: application/json and application/yaml. Encoding and
// decoding delegate to ns unchanged. Anything else the source factory carries
// (protobuf today, CBOR behind a feature gate) is deliberately not offered.
//
// The apoxy API types are generated without protobuf marshallers. The
// upstream codec factory still advertises protobuf, so a client that prefers
// it wins the negotiation and then gets 406 NotAcceptable at write time
// instead of a JSON answer. The Kubernetes namespace controller sends exactly
// that Accept header when it lists and deletes the contents of a namespace,
// and it treats the 406 as a permanent failure, which keeps the namespace in
// Terminating. Advertising only the supported types makes negotiation fall
// back to JSON.
func WithJSONAndYAML(ns runtime.NegotiatedSerializer) runtime.NegotiatedSerializer {
	accepts := make([]runtime.SerializerInfo, 0, 2)
	for _, info := range ns.SupportedMediaTypes() {
		switch info.MediaType {
		case runtime.ContentTypeJSON, runtime.ContentTypeYAML:
			accepts = append(accepts, info)
		}
	}
	return &jsonYAMLSerializer{NegotiatedSerializer: ns, accepts: accepts}
}

// jsonYAMLSerializer restricts content negotiation to JSON and YAML.
type jsonYAMLSerializer struct {
	runtime.NegotiatedSerializer

	accepts []runtime.SerializerInfo
}

func (s *jsonYAMLSerializer) SupportedMediaTypes() []runtime.SerializerInfo {
	return s.accepts
}
