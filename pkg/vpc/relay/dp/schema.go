// SPDX-License-Identifier: AGPL-3.0-only

package dp

import (
	_ "embed"
	"strings"

	p4config "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/types/known/anypb"

	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

//go:embed relay.p4info.txtpb
var p4infoText []byte

// P4Info returns the built-in schema of the pipeline: relay.p4info.txtpb and the PspSa extern,
// which p4test does not write for v1model.
func P4Info() (*p4config.P4Info, error) {
	info := &p4config.P4Info{}
	if err := prototext.Unmarshal(p4infoText, info); err != nil {
		return nil, err
	}
	_, alias, _ := strings.Cut(externKeysName, ".")
	info.Externs = append(info.Externs, &p4config.Extern{
		ExternTypeId:   ExternPspSa,
		ExternTypeName: "PspSa",
		Instances: []*p4config.ExternInstance{{
			Preamble: &p4config.Preamble{Id: ExternKeys, Name: externKeysName, Alias: alias},
		}},
	})
	return info, nil
}

// KeysEntry returns the ExternEntry of the keys extern that carries e.
func KeysEntry(e *dpv1.PspSaEntry) (*p4.ExternEntry, error) {
	a, err := anypb.New(e)
	if err != nil {
		return nil, err
	}
	return &p4.ExternEntry{ExternTypeId: ExternPspSa, ExternId: ExternKeys, Entry: a}, nil
}
