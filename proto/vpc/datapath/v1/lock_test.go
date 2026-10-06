// SPDX-License-Identifier: AGPL-3.0-only

package datapathv1_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// lockFile has the descriptors of the proto files at the last release, as a
// FileDescriptorSet in JSON. README.md tells when to update it.
const lockFile = "testdata/descriptors.lock.json"

var updateLock = flag.Bool("update", false, "write the descriptors of the proto files to "+lockFile)

// descriptors returns the descriptors of all proto files of the package.
func descriptors() *descriptorpb.FileDescriptorSet {
	var files []protoreflect.FileDescriptor
	protoregistry.GlobalFiles.RangeFilesByPackage(dp.File_proto_vpc_datapath_v1_types_proto.Package(), func(f protoreflect.FileDescriptor) bool {
		files = append(files, f)
		return true
	})
	slices.SortFunc(files, func(a, b protoreflect.FileDescriptor) int { return strings.Compare(a.Path(), b.Path()) })
	set := &descriptorpb.FileDescriptorSet{}
	for _, f := range files {
		set.File = append(set.File, protodesc.ToFileDescriptorProto(f))
	}
	return set
}

// TestDescriptorLock checks that the proto files only add to the locked
// descriptors, so that a build of the last release can read this build.
func TestDescriptorLock(t *testing.T) {
	now := descriptors()
	require.NotEmpty(t, now.GetFile())
	if *updateLock {
		b, err := protojson.Marshal(now)
		require.NoError(t, err)
		// protojson does not keep its spaces the same between builds. Indent does.
		var out bytes.Buffer
		require.NoError(t, json.Indent(&out, b, "", "  "))
		out.WriteByte('\n')
		require.NoError(t, os.MkdirAll(filepath.Dir(lockFile), 0o755))
		require.NoError(t, os.WriteFile(lockFile, out.Bytes(), 0o644))
		return
	}
	b, err := os.ReadFile(lockFile)
	require.NoError(t, err)
	locked := &descriptorpb.FileDescriptorSet{}
	require.NoError(t, protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, locked))
	require.NotEmpty(t, locked.GetFile())
	for _, br := range breaks(locked, now) {
		t.Error(br)
	}
	if t.Failed() {
		t.Log("An older build cannot read these changes. README.md has the rules for a change.")
	}
}

// schema has the messages, enums and services of a descriptor set by full
// name. The name lists keep the order of the files.
type schema struct {
	messages                              map[string]*descriptorpb.DescriptorProto
	enums                                 map[string]*descriptorpb.EnumDescriptorProto
	services                              map[string]*descriptorpb.ServiceDescriptorProto
	messageNames, enumNames, serviceNames []string
}

func index(set *descriptorpb.FileDescriptorSet) *schema {
	s := &schema{
		messages: map[string]*descriptorpb.DescriptorProto{},
		enums:    map[string]*descriptorpb.EnumDescriptorProto{},
		services: map[string]*descriptorpb.ServiceDescriptorProto{},
	}
	for _, f := range set.GetFile() {
		for _, m := range f.GetMessageType() {
			s.addMessage(f.GetPackage(), m)
		}
		for _, e := range f.GetEnumType() {
			s.addEnum(f.GetPackage(), e)
		}
		for _, sv := range f.GetService() {
			name := f.GetPackage() + "." + sv.GetName()
			s.services[name], s.serviceNames = sv, append(s.serviceNames, name)
		}
	}
	return s
}

func (s *schema) addMessage(scope string, m *descriptorpb.DescriptorProto) {
	name := scope + "." + m.GetName()
	s.messages[name], s.messageNames = m, append(s.messageNames, name)
	for _, n := range m.GetNestedType() {
		s.addMessage(name, n)
	}
	for _, e := range m.GetEnumType() {
		s.addEnum(name, e)
	}
}

func (s *schema) addEnum(scope string, e *descriptorpb.EnumDescriptorProto) {
	name := scope + "." + e.GetName()
	s.enums[name], s.enumNames = e, append(s.enumNames, name)
}

// breaks returns the changes from the locked descriptors to the current ones
// that an older build cannot read. A change that only adds is not in the result.
func breaks(locked, current *descriptorpb.FileDescriptorSet) []string {
	was, now := index(locked), index(current)
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	for _, name := range was.messageNames {
		m, ok := now.messages[name]
		if !ok {
			add("message %s is removed", name)
			continue
		}
		fieldBreaks(name, was.messages[name], m, add)
	}
	for _, name := range was.enumNames {
		e, ok := now.enums[name]
		if !ok {
			add("enum %s is removed", name)
			continue
		}
		valueBreaks(name, was.enums[name], e, add)
	}
	for _, name := range was.serviceNames {
		s, ok := now.services[name]
		if !ok {
			add("service %s is removed", name)
			continue
		}
		methodBreaks(name, was.services[name], s, add)
	}
	return out
}

// fieldBreaks adds the changes to the fields of message name.
func fieldBreaks(name string, was, now *descriptorpb.DescriptorProto, add func(string, ...any)) {
	for _, f := range was.GetField() {
		num, field := f.GetNumber(), name+"."+f.GetName()
		i := slices.IndexFunc(now.GetField(), func(c *descriptorpb.FieldDescriptorProto) bool { return c.GetNumber() == num })
		if i < 0 {
			j := slices.IndexFunc(now.GetField(), func(c *descriptorpb.FieldDescriptorProto) bool { return c.GetName() == f.GetName() })
			if j >= 0 {
				add("field %s changed its number from %d to %d", field, num, now.GetField()[j].GetNumber())
				continue
			}
			// The range of a message has an open end.
			if !slices.ContainsFunc(now.GetReservedRange(), func(r *descriptorpb.DescriptorProto_ReservedRange) bool {
				return r.GetStart() <= num && num < r.GetEnd()
			}) {
				add("field %s is removed, and its number %d is not reserved", field, num)
			}
			if !slices.Contains(now.GetReservedName(), f.GetName()) {
				add("field %s is removed, and its name is not reserved", field)
			}
			continue
		}
		cur := now.GetField()[i]
		if cur.GetName() != f.GetName() {
			add("field %d of %s changed its name from %s to %s", num, name, f.GetName(), cur.GetName())
		}
		if a, b := fieldType(f), fieldType(cur); a != b {
			add("field %s changed its type from %s to %s", field, a, b)
		}
		if a, b := cardinality(was, f), cardinality(now, cur); a != b {
			add("field %s changed its cardinality from %s to %s", field, a, b)
		}
	}
}

// fieldType returns the type of f: the scalar type, or the full name of its
// message or enum.
func fieldType(f *descriptorpb.FieldDescriptorProto) string {
	if n := f.GetTypeName(); n != "" {
		return strings.TrimPrefix(n, ".")
	}
	return strings.ToLower(strings.TrimPrefix(f.GetType().String(), "TYPE_"))
}

// cardinality tells how many values f of message m can have. A field of a
// oneof shares its one value with the other fields of the oneof.
func cardinality(m *descriptorpb.DescriptorProto, f *descriptorpb.FieldDescriptorProto) string {
	switch {
	case f.GetLabel() == descriptorpb.FieldDescriptorProto_LABEL_REPEATED:
		return "repeated"
	case f.GetLabel() == descriptorpb.FieldDescriptorProto_LABEL_REQUIRED:
		return "required"
	case f.GetProto3Optional():
		return "optional"
	case f.OneofIndex != nil:
		return "oneof " + m.GetOneofDecl()[f.GetOneofIndex()].GetName()
	}
	return "singular"
}

// valueBreaks adds the changes to the values of enum name.
func valueBreaks(name string, was, now *descriptorpb.EnumDescriptorProto, add func(string, ...any)) {
	for _, v := range was.GetValue() {
		num, value := v.GetNumber(), name+"."+v.GetName()
		i := slices.IndexFunc(now.GetValue(), func(c *descriptorpb.EnumValueDescriptorProto) bool { return c.GetName() == v.GetName() })
		if i >= 0 {
			if n := now.GetValue()[i].GetNumber(); n != num {
				add("enum value %s changed its number from %d to %d", value, num, n)
			}
			continue
		}
		j := slices.IndexFunc(now.GetValue(), func(c *descriptorpb.EnumValueDescriptorProto) bool { return c.GetNumber() == num })
		if j >= 0 {
			add("enum value %d of %s changed its name from %s to %s", num, name, v.GetName(), now.GetValue()[j].GetName())
			continue
		}
		// The range of an enum includes its end.
		if !slices.ContainsFunc(now.GetReservedRange(), func(r *descriptorpb.EnumDescriptorProto_EnumReservedRange) bool {
			return r.GetStart() <= num && num <= r.GetEnd()
		}) {
			add("enum value %s is removed, and its number %d is not reserved", value, num)
		}
		if !slices.Contains(now.GetReservedName(), v.GetName()) {
			add("enum value %s is removed, and its name is not reserved", value)
		}
	}
}

// methodBreaks adds the changes to the methods of service name.
func methodBreaks(name string, was, now *descriptorpb.ServiceDescriptorProto, add func(string, ...any)) {
	for _, m := range was.GetMethod() {
		method := name + "." + m.GetName()
		i := slices.IndexFunc(now.GetMethod(), func(c *descriptorpb.MethodDescriptorProto) bool { return c.GetName() == m.GetName() })
		if i < 0 {
			add("method %s is removed", method)
			continue
		}
		cur := now.GetMethod()[i]
		if a, b := m.GetInputType(), cur.GetInputType(); a != b {
			add("method %s changed its input from %s to %s", method, strings.TrimPrefix(a, "."), strings.TrimPrefix(b, "."))
		}
		if a, b := m.GetOutputType(), cur.GetOutputType(); a != b {
			add("method %s changed its output from %s to %s", method, strings.TrimPrefix(a, "."), strings.TrimPrefix(b, "."))
		}
		if a, b := m.GetClientStreaming(), cur.GetClientStreaming(); a != b {
			add("method %s changed its client streaming from %t to %t", method, a, b)
		}
		if a, b := m.GetServerStreaming(), cur.GetServerStreaming(); a != b {
			add("method %s changed its server streaming from %t to %t", method, a, b)
		}
	}
}

// lockSchema is the locked schema of TestBreaks.
const lockSchema = `
file {
  name: "lock.proto"
  package: "lock"
  syntax: "proto3"
  message_type {
    name: "Msg"
    field { name: "id" number: 1 type: TYPE_UINT32 label: LABEL_OPTIONAL }
    field { name: "tags" number: 2 type: TYPE_STRING label: LABEL_REPEATED }
    field { name: "kind" number: 3 type: TYPE_ENUM type_name: ".lock.Kind" label: LABEL_OPTIONAL }
    field { name: "inner" number: 4 type: TYPE_MESSAGE type_name: ".lock.Msg.Inner" label: LABEL_OPTIONAL }
    field { name: "text" number: 5 type: TYPE_STRING label: LABEL_OPTIONAL oneof_index: 0 }
    field { name: "data" number: 6 type: TYPE_BYTES label: LABEL_OPTIONAL oneof_index: 0 }
    nested_type {
      name: "Inner"
      field { name: "x" number: 1 type: TYPE_BYTES label: LABEL_OPTIONAL }
      enum_type { name: "State" value { name: "STATE_UNSPECIFIED" number: 0 } }
    }
    oneof_decl { name: "body" }
  }
  message_type { name: "Other" }
  enum_type {
    name: "Kind"
    value { name: "KIND_UNSPECIFIED" number: 0 }
    value { name: "KIND_A" number: 1 }
    value { name: "KIND_B" number: 2 }
  }
  service {
    name: "Svc"
    method { name: "Call" input_type: ".lock.Msg" output_type: ".lock.Other" }
    method { name: "Watch" input_type: ".lock.Msg" output_type: ".lock.Other" server_streaming: true }
  }
}`

// TestBreaks changes a locked schema in one way for each case.
func TestBreaks(t *testing.T) {
	locked := &descriptorpb.FileDescriptorSet{}
	require.NoError(t, prototext.Unmarshal([]byte(lockSchema), locked))
	_, err := protodesc.NewFiles(locked)
	require.NoError(t, err, "the locked schema is not valid")

	type (
		file    = descriptorpb.FileDescriptorProto
		message = descriptorpb.DescriptorProto
		field   = descriptorpb.FieldDescriptorProto
		value   = descriptorpb.EnumValueDescriptorProto
		method  = descriptorpb.MethodDescriptorProto
	)
	optional, repeated := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	str, u64 := descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum()
	// The helpers find the parts of the schema that the cases change.
	msg := func(f *file) *message { return f.MessageType[0] }
	fieldOf := func(f *file, name string) *field {
		m := msg(f)
		return m.Field[slices.IndexFunc(m.Field, func(x *field) bool { return x.GetName() == name })]
	}
	dropField := func(f *file, name string) {
		m := msg(f)
		m.Field = slices.DeleteFunc(m.Field, func(x *field) bool { return x.GetName() == name })
	}
	kind := func(f *file) *descriptorpb.EnumDescriptorProto { return f.EnumType[0] }
	dropValue := func(f *file, name string) {
		e := kind(f)
		e.Value = slices.DeleteFunc(e.Value, func(x *value) bool { return x.GetName() == name })
	}
	call := func(f *file) *method { return f.Service[0].Method[0] }

	cases := []struct {
		name   string
		change func(f *file)
		want   []string // The breaks. Empty means that the change passes.
	}{
		{name: "no change", change: func(*file) {}},

		// Changes that only add.
		{name: "new field", change: func(f *file) {
			msg(f).Field = append(msg(f).Field, &field{Name: proto.String("more"), Number: proto.Int32(7), Type: str, Label: optional})
		}},
		{name: "new field in a oneof", change: func(f *file) {
			msg(f).Field = append(msg(f).Field, &field{Name: proto.String("more"), Number: proto.Int32(7), Type: str, Label: optional, OneofIndex: proto.Int32(0)})
		}},
		{name: "new nested message", change: func(f *file) {
			msg(f).NestedType = append(msg(f).NestedType, &message{Name: proto.String("More")})
		}},
		{name: "new message", change: func(f *file) { f.MessageType = append(f.MessageType, &message{Name: proto.String("More")}) }},
		{name: "new enum value", change: func(f *file) {
			kind(f).Value = append(kind(f).Value, &value{Name: proto.String("KIND_C"), Number: proto.Int32(3)})
		}},
		{name: "new enum", change: func(f *file) {
			f.EnumType = append(f.EnumType, &descriptorpb.EnumDescriptorProto{Name: proto.String("More"), Value: []*value{{Name: proto.String("MORE_UNSPECIFIED"), Number: proto.Int32(0)}}})
		}},
		{name: "new method", change: func(f *file) {
			f.Service[0].Method = append(f.Service[0].Method, &method{Name: proto.String("More"), InputType: proto.String(".lock.Msg"), OutputType: proto.String(".lock.Other")})
		}},
		{name: "new service", change: func(f *file) {
			f.Service = append(f.Service, &descriptorpb.ServiceDescriptorProto{Name: proto.String("More")})
		}},
		{name: "new file path", change: func(f *file) { f.Name = proto.String("moved.proto") }},

		// Removals that reserve the number and the name.
		{name: "field removed with its number and name reserved", change: func(f *file) {
			dropField(f, "tags")
			msg(f).ReservedRange = []*descriptorpb.DescriptorProto_ReservedRange{{Start: proto.Int32(2), End: proto.Int32(3)}}
			msg(f).ReservedName = []string{"tags"}
		}},
		{name: "enum value removed with its number and name reserved", change: func(f *file) {
			dropValue(f, "KIND_B")
			kind(f).ReservedRange = []*descriptorpb.EnumDescriptorProto_EnumReservedRange{{Start: proto.Int32(2), End: proto.Int32(2)}}
			kind(f).ReservedName = []string{"KIND_B"}
		}},

		// Fields.
		{
			name:   "field number changes",
			change: func(f *file) { fieldOf(f, "id").Number = proto.Int32(9) },
			want:   []string{"field lock.Msg.id changed its number from 1 to 9"},
		},
		{
			name:   "field type changes",
			change: func(f *file) { fieldOf(f, "id").Type = u64 },
			want:   []string{"field lock.Msg.id changed its type from uint32 to uint64"},
		},
		{
			name:   "field message type changes",
			change: func(f *file) { fieldOf(f, "inner").TypeName = proto.String(".lock.Other") },
			want:   []string{"field lock.Msg.inner changed its type from lock.Msg.Inner to lock.Other"},
		},
		{
			name:   "field name changes",
			change: func(f *file) { fieldOf(f, "id").Name = proto.String("ident") },
			want:   []string{"field 1 of lock.Msg changed its name from id to ident"},
		},
		{
			name:   "singular field becomes repeated",
			change: func(f *file) { fieldOf(f, "id").Label = repeated },
			want:   []string{"field lock.Msg.id changed its cardinality from singular to repeated"},
		},
		{
			name:   "repeated field becomes singular",
			change: func(f *file) { fieldOf(f, "tags").Label = optional },
			want:   []string{"field lock.Msg.tags changed its cardinality from repeated to singular"},
		},
		{
			name: "singular field becomes optional",
			change: func(f *file) {
				msg(f).OneofDecl = append(msg(f).OneofDecl, &descriptorpb.OneofDescriptorProto{Name: proto.String("_id")})
				fieldOf(f, "id").Proto3Optional, fieldOf(f, "id").OneofIndex = proto.Bool(true), proto.Int32(1)
			},
			want: []string{"field lock.Msg.id changed its cardinality from singular to optional"},
		},
		{
			name:   "field leaves its oneof",
			change: func(f *file) { fieldOf(f, "text").OneofIndex = nil },
			want:   []string{"field lock.Msg.text changed its cardinality from oneof body to singular"},
		},
		{
			name:   "field joins a oneof",
			change: func(f *file) { fieldOf(f, "id").OneofIndex = proto.Int32(0) },
			want:   []string{"field lock.Msg.id changed its cardinality from singular to oneof body"},
		},
		{
			name:   "field of a nested message changes",
			change: func(f *file) { msg(f).NestedType[0].Field[0].Type = str },
			want:   []string{"field lock.Msg.Inner.x changed its type from bytes to string"},
		},
		{
			name:   "field removed",
			change: func(f *file) { dropField(f, "tags") },
			want: []string{
				"field lock.Msg.tags is removed, and its number 2 is not reserved",
				"field lock.Msg.tags is removed, and its name is not reserved",
			},
		},
		{
			name: "field removed with only its number reserved",
			change: func(f *file) {
				dropField(f, "tags")
				msg(f).ReservedRange = []*descriptorpb.DescriptorProto_ReservedRange{{Start: proto.Int32(2), End: proto.Int32(3)}}
			},
			want: []string{"field lock.Msg.tags is removed, and its name is not reserved"},
		},
		{
			name: "field removed with only its name reserved",
			change: func(f *file) {
				dropField(f, "tags")
				// The end of the range is open, so this range has only the number 1.
				msg(f).ReservedRange = []*descriptorpb.DescriptorProto_ReservedRange{{Start: proto.Int32(1), End: proto.Int32(2)}}
				msg(f).ReservedName = []string{"tags"}
			},
			want: []string{"field lock.Msg.tags is removed, and its number 2 is not reserved"},
		},

		// Enums.
		{
			name:   "enum value number changes",
			change: func(f *file) { kind(f).Value[2].Number = proto.Int32(5) },
			want:   []string{"enum value lock.Kind.KIND_B changed its number from 2 to 5"},
		},
		{
			name:   "enum value name changes",
			change: func(f *file) { kind(f).Value[2].Name = proto.String("KIND_C") },
			want:   []string{"enum value 2 of lock.Kind changed its name from KIND_B to KIND_C"},
		},
		{
			name:   "enum value removed",
			change: func(f *file) { dropValue(f, "KIND_B") },
			want: []string{
				"enum value lock.Kind.KIND_B is removed, and its number 2 is not reserved",
				"enum value lock.Kind.KIND_B is removed, and its name is not reserved",
			},
		},
		{
			name: "enum value removed with only its number reserved",
			change: func(f *file) {
				dropValue(f, "KIND_B")
				kind(f).ReservedRange = []*descriptorpb.EnumDescriptorProto_EnumReservedRange{{Start: proto.Int32(2), End: proto.Int32(2)}}
			},
			want: []string{"enum value lock.Kind.KIND_B is removed, and its name is not reserved"},
		},
		{
			name: "enum value removed with only its name reserved",
			change: func(f *file) {
				dropValue(f, "KIND_B")
				kind(f).ReservedRange = []*descriptorpb.EnumDescriptorProto_EnumReservedRange{{Start: proto.Int32(3), End: proto.Int32(9)}}
				kind(f).ReservedName = []string{"KIND_B"}
			},
			want: []string{"enum value lock.Kind.KIND_B is removed, and its number 2 is not reserved"},
		},
		{
			name:   "enum removed",
			change: func(f *file) { f.EnumType = nil },
			want:   []string{"enum lock.Kind is removed"},
		},
		{
			name:   "nested enum removed",
			change: func(f *file) { msg(f).NestedType[0].EnumType = nil },
			want:   []string{"enum lock.Msg.Inner.State is removed"},
		},

		// Messages, services and methods.
		{
			name:   "message removed",
			change: func(f *file) { f.MessageType = f.MessageType[:1] },
			want:   []string{"message lock.Other is removed"},
		},
		{
			name:   "nested message removed",
			change: func(f *file) { msg(f).NestedType = nil },
			want:   []string{"message lock.Msg.Inner is removed", "enum lock.Msg.Inner.State is removed"},
		},
		{
			name:   "package changes",
			change: func(f *file) { f.Package = proto.String("other") },
			want: []string{
				"message lock.Msg is removed", "message lock.Msg.Inner is removed", "message lock.Other is removed",
				"enum lock.Msg.Inner.State is removed", "enum lock.Kind is removed", "service lock.Svc is removed",
			},
		},
		{
			name:   "service removed",
			change: func(f *file) { f.Service = nil },
			want:   []string{"service lock.Svc is removed"},
		},
		{
			name:   "method removed",
			change: func(f *file) { f.Service[0].Method = f.Service[0].Method[:1] },
			want:   []string{"method lock.Svc.Watch is removed"},
		},
		{
			name:   "method input changes",
			change: func(f *file) { call(f).InputType = proto.String(".lock.Other") },
			want:   []string{"method lock.Svc.Call changed its input from lock.Msg to lock.Other"},
		},
		{
			name:   "method output changes",
			change: func(f *file) { call(f).OutputType = proto.String(".lock.Msg") },
			want:   []string{"method lock.Svc.Call changed its output from lock.Other to lock.Msg"},
		},
		{
			name:   "method becomes client streaming",
			change: func(f *file) { call(f).ClientStreaming = proto.Bool(true) },
			want:   []string{"method lock.Svc.Call changed its client streaming from false to true"},
		},
		{
			name:   "method becomes server streaming",
			change: func(f *file) { call(f).ServerStreaming = proto.Bool(true) },
			want:   []string{"method lock.Svc.Call changed its server streaming from false to true"},
		},
		{
			name:   "method stops server streaming",
			change: func(f *file) { f.Service[0].Method[1].ServerStreaming = nil },
			want:   []string{"method lock.Svc.Watch changed its server streaming from true to false"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := proto.Clone(locked).(*descriptorpb.FileDescriptorSet)
			tc.change(current.File[0])
			assert.Equal(t, tc.want, breaks(locked, current))
		})
	}
}
