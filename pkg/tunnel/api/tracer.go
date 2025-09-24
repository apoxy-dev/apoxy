package api

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/logging"
)

func newConnectionTracer(ctx context.Context, p logging.Perspective, odcid logging.ConnectionID) *logging.ConnectionTracer {
	return &logging.ConnectionTracer{
		StartedConnection: func(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
			slog.Debug("Started connection",
				slog.String("local", local.String()), slog.String("remote", remote.String()),
				slog.String("src_conn_id", srcConnID.String()), slog.String("dest_conn_id", destConnID.String()))
		},
		NegotiatedVersion: func(chosen logging.Version, clientVersions, serverVersions []logging.Version) {
			slog.Debug("Negotiated version", slog.String("version", chosen.String()))
		},
		ClosedConnection: func(err error) {
			slog.Debug("Closed connection", slog.String("odcid", odcid.String()), slog.Any("error", err))
		},
		SentTransportParameters: func(parameters *logging.TransportParameters) {
			slog.Debug("Sent transport parameters", slog.String("odcid", odcid.String()))
		},
		ReceivedTransportParameters: func(parameters *logging.TransportParameters) {
			slog.Debug("Received transport parameters", slog.String("odcid", odcid.String()))
		},
		RestoredTransportParameters: func(parameters *logging.TransportParameters) {
			// for 0-RTT
			slog.Debug("Restored transport parameters", slog.String("odcid", odcid.String()))
		},
		SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			slog.Debug("Sent long header packet", slog.String("odcid", odcid.String()))
		},
		SentShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			slog.Debug("Sent short header packet", slog.String("odcid", odcid.String()))
		},
		ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, versions []logging.Version) {
			slog.Debug("Received version negotiation packet", slog.String("odcid", odcid.String()))
		},
		ReceivedRetry: func(hdr *logging.Header) {
			slog.Debug("Received retry", slog.String("odcid", odcid.String()))
		},
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			slog.Debug("Received long header packet", slog.String("odcid", odcid.String()))
		},
		ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			slog.Debug("Received short header packet", slog.String("odcid", odcid.String()))
		},
		BufferedPacket: func(packetType logging.PacketType, size logging.ByteCount) {
			slog.Debug("Buffered packet", slog.String("odcid", odcid.String()))
		},
		DroppedPacket: func(packetType logging.PacketType, pn logging.PacketNumber, size logging.ByteCount, reason logging.PacketDropReason) {
			slog.Debug("Dropped packet", slog.String("odcid", odcid.String()), slog.Int("reason", int(reason)))
		},
		UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
			slog.Debug("Updated metrics", slog.String("odcid", odcid.String()))
		},
		AcknowledgedPacket: func(encLevel logging.EncryptionLevel, pn logging.PacketNumber) {
			slog.Debug("Acknowledged packet", slog.String("odcid", odcid.String()))
		},
		LostPacket: func(encLevel logging.EncryptionLevel, pn logging.PacketNumber, reason logging.PacketLossReason) {
			slog.Debug("Lost packet", slog.String("odcid", odcid.String()), slog.Int("reason", int(reason)))
		},
		UpdatedMTU: func(mtu logging.ByteCount, done bool) {
			slog.Debug("Updated MTU", slog.String("odcid", odcid.String()), slog.Int("mtu", int(mtu)), slog.Bool("done", done))
		},
		UpdatedCongestionState: func(state logging.CongestionState) {
			slog.Debug("Updated congestion state", slog.String("odcid", odcid.String()), slog.Int("state", int(state)))
		},
		UpdatedPTOCount: func(value uint32) {
			slog.Debug("Updated PTO count", slog.String("odcid", odcid.String()), slog.Uint64("value", uint64(value)))
		},
		UpdatedKeyFromTLS: func(encLevel logging.EncryptionLevel, p logging.Perspective) {
			slog.Debug("Updated key from TLS", slog.String("odcid", odcid.String()),
				slog.String("enc_level", strconv.Itoa(int(encLevel))), slog.String("perspective", p.String()))
		},
		UpdatedKey: func(keyPhase logging.KeyPhase, remote bool) {
			slog.Debug("Updated key", slog.String("odcid", odcid.String()),
				slog.String("key_phase", strconv.Itoa(int(keyPhase))), slog.Bool("remote", remote))
		},
		DroppedEncryptionLevel: func(encLevel logging.EncryptionLevel) {
			slog.Debug("Dropped encryption level", slog.String("odcid", odcid.String()), slog.String("enc_level", strconv.Itoa(int(encLevel))))
		},
		DroppedKey: func(keyPhase logging.KeyPhase) {
			slog.Debug("Dropped key", slog.String("odcid", odcid.String()), slog.String("key_phase", strconv.Itoa(int(keyPhase))))
		},
		SetLossTimer: func(timerType logging.TimerType, encLevel logging.EncryptionLevel, time time.Time) {
			slog.Debug("Set loss timer", slog.String("odcid", odcid.String()), slog.String("timer_type", strconv.Itoa(int(timerType))), slog.String("enc_level", strconv.Itoa(int(encLevel))), slog.Time("time", time))
		},
		LossTimerExpired: func(timerType logging.TimerType, encLevel logging.EncryptionLevel) {
			slog.Debug("Loss timer expired", slog.String("odcid", odcid.String()), slog.String("timer_type", strconv.Itoa(int(timerType))), slog.String("enc_level", strconv.Itoa(int(encLevel))))
		},
		LossTimerCanceled: func() {
			slog.Debug("Loss timer canceled", slog.String("odcid", odcid.String()))
		},
		ECNStateUpdated: func(state logging.ECNState, trigger logging.ECNStateTrigger) {
			slog.Debug("ECN state updated", slog.String("odcid", odcid.String()), slog.Int("state", int(state)), slog.Int("trigger", int(trigger)))
		},
		ChoseALPN: func(protocol string) {
			slog.Debug("Chose ALPN", slog.String("odcid", odcid.String()), slog.String("protocol", protocol))
		},
		Close: func() {
			slog.Debug("Connection closed", slog.String("odcid", odcid.String()))
		},
		Debug: func(name, msg string) {
			slog.Debug("QUIC debug", slog.String("odcid", odcid.String()), slog.String("name", name), slog.String("msg", msg))
		},
	}
}
