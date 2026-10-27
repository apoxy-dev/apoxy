// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// textFile writes m as p4c writes a P4Info text file (writeTextTo in
// control-plane/p4RuntimeSerializer.cpp): two header lines, then the C++ protobuf TextFormat
// layout. Go's prototext has a different layout, so CI could not compare its output with diff.
func textFile(m proto.Message) []byte {
	var b bytes.Buffer
	d := m.ProtoReflect().Descriptor()
	fmt.Fprintf(&b, "# proto-file: %s\n# proto-message: %s\n\n", d.ParentFile().Path(), d.FullName())
	writeMessage(&b, m.ProtoReflect(), 0)
	return b.Bytes()
}

// writeMessage writes the set fields of m in field number order, two spaces for each level.
func writeMessage(b *bytes.Buffer, m protoreflect.Message, depth int) {
	var fields []protoreflect.FieldDescriptor
	m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		fields = append(fields, fd)
		return true
	})
	slices.SortFunc(fields, func(a, b protoreflect.FieldDescriptor) int { return int(a.Number() - b.Number()) })
	for _, fd := range fields {
		v := m.Get(fd)
		switch {
		case fd.IsMap():
			// TextFormat writes a map as entries with key and value, sorted by key.
			mp := v.Map()
			var keys []protoreflect.MapKey
			mp.Range(func(k protoreflect.MapKey, _ protoreflect.Value) bool {
				keys = append(keys, k)
				return true
			})
			slices.SortFunc(keys, func(a, b protoreflect.MapKey) int { return strings.Compare(a.String(), b.String()) })
			for _, k := range keys {
				indent(b, depth)
				fmt.Fprintf(b, "%s {\n", fd.Name())
				writeField(b, fd.MapKey(), k.Value(), depth+1)
				writeField(b, fd.MapValue(), mp.Get(k), depth+1)
				indent(b, depth)
				b.WriteString("}\n")
			}
		case fd.IsList():
			l := v.List()
			for i := range l.Len() {
				writeField(b, fd, l.Get(i), depth)
			}
		default:
			writeField(b, fd, v, depth)
		}
	}
}

func writeField(b *bytes.Buffer, fd protoreflect.FieldDescriptor, v protoreflect.Value, depth int) {
	indent(b, depth)
	switch fd.Kind() {
	case protoreflect.MessageKind:
		fmt.Fprintf(b, "%s {\n", fd.Name())
		writeMessage(b, v.Message(), depth+1)
		indent(b, depth)
		b.WriteString("}\n")
		return
	case protoreflect.EnumKind:
		if ev := fd.Enum().Values().ByNumber(v.Enum()); ev != nil {
			fmt.Fprintf(b, "%s: %s\n", fd.Name(), ev.Name())
		} else {
			fmt.Fprintf(b, "%s: %d\n", fd.Name(), v.Enum())
		}
		return
	case protoreflect.StringKind:
		fmt.Fprintf(b, "%s: \"%s\"\n", fd.Name(), cEscape([]byte(v.String())))
		return
	case protoreflect.BytesKind:
		fmt.Fprintf(b, "%s: \"%s\"\n", fd.Name(), cEscape(v.Bytes()))
		return
	case protoreflect.BoolKind:
		fmt.Fprintf(b, "%s: %t\n", fd.Name(), v.Bool())
		return
	}
	fmt.Fprintf(b, "%s: %v\n", fd.Name(), v.Interface())
}

func indent(b *bytes.Buffer, depth int) {
	for range depth {
		b.WriteString("  ")
	}
}

// cEscape escapes s as the CEscape of the C++ protobuf library: the C escapes for newline,
// tab, quotes and backslash, and three octal digits for other bytes that are not printable.
func cEscape(s []byte) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '"':
			b.WriteString(`\"`)
		case '\'':
			b.WriteString(`\'`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, `\%03o`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
