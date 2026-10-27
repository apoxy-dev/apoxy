// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"slices"
	"strings"
)

// The P4Runtime type prefix of PspSa, the first ID for the externs of other architectures.
const pspSaType = 0x81

// assignIDs gives each name of each type prefix an ID as p4c does it
// (control-plane/p4RuntimeSymbolTable.cpp, lines 227-283, p4c v1.2.5.18): the prefix in the
// top 8 bits and the Jenkins one-at-a-time hash of the full name in the low 24 bits. The
// prefixes go in increasing order and the names of a prefix in sorted order. On a collision
// the hash goes up by 1 until the ID is free (probeForId in p4RuntimeSymbolTable.h).
func assignIDs(names map[uint32][]string) (map[uint32]map[string]uint32, error) {
	used := map[uint32]bool{}
	ids := map[uint32]map[string]uint32{}
	prefixes := make([]uint32, 0, len(names))
	for p := range names {
		prefixes = append(prefixes, p)
	}
	slices.Sort(prefixes)
	for _, p := range prefixes {
		ids[p] = map[string]uint32{}
		sorted := slices.Clone(names[p])
		slices.Sort(sorted)
		for _, n := range slices.Compact(sorted) {
			start := jenkins(n)
			h := start
			for used[p<<24|h&0xffffff] {
				h++
				if h == start {
					return nil, fmt.Errorf("no free P4Runtime ID for %s", n)
				}
			}
			id := p<<24 | h&0xffffff
			used[id] = true
			ids[p][n] = id
		}
	}
	return ids, nil
}

// jenkins is the one-at-a-time hash of p4c (jenkinsOneAtATimeHash).
func jenkins(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h += uint32(s[i])
		h += h << 10
		h ^= h >> 6
	}
	h += h << 3
	h ^= h >> 11
	h += h << 15
	return h
}

// aliases gives each name the shortest suffix of dot-separated parts that no other name has, as
// P4SymbolSuffixSet::shortestUniqueSuffix in p4RuntimeSymbolTable.cpp does.
func aliases(names []string) map[string]string {
	count := map[string]int{} // The number of names with each suffix.
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	for _, n := range names {
		parts := strings.Split(n, ".")
		for i := range parts {
			count[strings.Join(parts[i:], ".")]++
		}
	}
	out := map[string]string{}
	for _, n := range names {
		parts := strings.Split(n, ".")
		i := len(parts) - 1
		for i > 0 && count[strings.Join(parts[i:], ".")] > 1 {
			i--
		}
		out[n] = strings.Join(parts[i:], ".")
	}
	return out
}
