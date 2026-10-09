// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// snapshotRevision is the first revision with the Snapshot call of the mesh.
	snapshotRevision = 14
	// snapshotPartSize is the most bytes of one part. A call message holds 4 MiB.
	snapshotPartSize = 1 << 20
	// maxSnapshotSize is the most bytes of a snapshot that a relay sends or takes.
	maxSnapshotSize = 64 << 20
	// snapshotTimeout limits the Snapshot call to one member.
	snapshotTimeout = 10 * time.Second
)

// Snapshot sends the snapshot of the host of this relay in parts. The caller is
// the member of an open session, so no other connection gets the bytes.
func (m *Mesh) Snapshot(ctx context.Context, _ *dp.SnapshotRequest, st rpc.ServerStreamServer[dp.SnapshotPart]) error {
	s, err := m.SessionOf(ctx)
	if err != nil {
		return err
	}
	var data []byte
	if m.cfg.Snapshot != nil {
		data = m.cfg.Snapshot()
	}
	switch {
	case len(data) == 0:
		return rpc.Errorf(rpc.NotFound, "relay host has no snapshot")
	case len(data) > maxSnapshotSize:
		slog.Warn("Refused to send a snapshot above the size limit", "relay", s.Name(), "bytes", len(data), "limit", maxSnapshotSize)
		return rpc.Errorf(rpc.ResourceExhausted, "snapshot of %d bytes is above the limit of %d", len(data), maxSnapshotSize)
	}
	// Only the first part has the size, so that the caller can refuse it before the bytes.
	size := uint64(len(data))
	for rest := data; len(rest) > 0; size = 0 {
		n := min(len(rest), snapshotPartSize)
		if err := st.Send(&dp.SnapshotPart{Data: rest[:n], TotalSize: size}); err != nil {
			return err
		}
		rest = rest[n:]
	}
	slog.Info("Sent the host snapshot to a mesh member", "relay", s.Name(), "bytes", len(data))
	return nil
}

// FetchSnapshot asks each member with an open session, in name order, and returns the
// first host snapshot and the name of its member. With none, the error code is NotFound.
func (m *Mesh) FetchSnapshot(ctx context.Context) (data []byte, from string, err error) {
	m.mu.Lock()
	var sessions []*MeshSession
	for _, mem := range m.members {
		// A relay from before the call does not have it, so it costs no call.
		if s := mem.sess; s != nil && s.version.GetRevision() >= snapshotRevision {
			sessions = append(sessions, s)
		}
	}
	m.mu.Unlock()
	slices.SortFunc(sessions, func(a, b *MeshSession) int { return strings.Compare(a.name, b.name) })
	for _, s := range sessions {
		b, err := fetchSnapshot(ctx, s)
		switch code := rpc.CodeOf(err); {
		case err == nil:
			slog.Info("Got the host snapshot of a mesh member", "relay", s.name, "bytes", len(b))
			return b, s.name, nil
		case ctx.Err() != nil:
			return nil, "", ctx.Err()
		case code == rpc.NotFound || code == rpc.Unimplemented:
			slog.Info("Mesh member has no host snapshot", "relay", s.name)
		default:
			slog.Warn("Failed to get the host snapshot of a mesh member", "relay", s.name, "error", err)
		}
	}
	return nil, "", rpc.Errorf(rpc.NotFound, "no member of the mesh gave a snapshot")
}

// fetchSnapshot gets the snapshot of the host of the member of s. The whole call
// has snapshotTimeout, which the member gets in the call header.
func fetchSnapshot(ctx context.Context, s *MeshSession) ([]byte, error) {
	// The end of ctx also ends a call that returns before the end of the stream.
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	st, err := s.client.Snapshot(ctx, &dp.SnapshotRequest{})
	if err != nil {
		return nil, err
	}
	var data []byte
	var total uint64
	for first := true; ; first = false {
		part, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if first {
			// The size check comes before the buffer, so a member cannot make this relay hold more.
			if total = part.GetTotalSize(); total > maxSnapshotSize {
				return nil, fmt.Errorf("snapshot size %d is above the limit of %d", total, maxSnapshotSize)
			}
			data = make([]byte, 0, total)
		}
		if uint64(len(data)+len(part.GetData())) > total {
			return nil, fmt.Errorf("snapshot has more bytes than its size of %d", total)
		}
		data = append(data, part.GetData()...)
	}
	if uint64(len(data)) != total || total == 0 {
		return nil, fmt.Errorf("snapshot ended after %d of %d bytes", len(data), total)
	}
	return data, nil
}
