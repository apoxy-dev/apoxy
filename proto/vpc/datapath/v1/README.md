# VPC datapath control: wire format

The control plane of VPC Tunnels v2. The `.proto` files here define the
messages and services. The runtime is `pkg/vpc/rpc`, and
`protoc-gen-go-vpcrpc` makes the Go stubs. Regenerate with
`go generate ./proto/vpc/datapath/v1`.

## Connections

QUIC v1, TLS 1.3 with mTLS, UDP 443. The ALPN selects the channel and the
service that each side serves:

| ALPN           | Between                  | Service | Served by |
|----------------|--------------------------|---------|-----------|
| `apoxy-vpc/2`  | agent or VTEP and relay  | `Relay` | relay     |
| `apoxy-peer/1` | agent and agent          | `Peer`  | both      |
| `apoxy-mesh/1` | relay and relay          | `Mesh`  | both      |

The same UDP socket also carries PSP packets (first byte `0x04` or `0x29`),
which relays forward by SPI rows without decryption. Only PSP packets to the
relay itself are opened (see "QUIC and PSP bridge").

### Relay datagrams

QUIC DATAGRAM frames on a relay session carry peer-session packets between
two agents in one VPC:

```
agent -> relay:  type (1 B) | dst address (16 B) | src address (16 B) | packet
relay -> agent:  type (1 B) | src address (16 B) | packet
type:            0x01 peer-session packet
```

Addresses are overlay addresses; IPv4 is in the IPv4-mapped form. The relay
drops a frame if its session does not route the source address (the same
rule as the PSP source check), if Permit denies the destination, or if no
session routes the destination. For the last two it sends `NoRoute`.

Peer sessions use 1200 B QUIC packets. Both ends of a relay session use a
QUIC InitialPacketSize of 1270 B or more, so that each packet fits in one
frame.

In QUIC mode, the same frames carry data:

```
data:            type (1 B) | VNI word (4 B) | inner IPv4 or IPv6 packet
type:            0x03 data frame
```

The VNI word is the first word of the PSP VC: the VNI (24 bits), then 8 flag
bits. The relay ignores the flags. It drops a data frame if the session is not
in QUIC mode, if the VNI is not the network ID of the session, if the session
does not route the inner source, if Permit denies the inner destination, or if
no session routes it (then it sends `NoRoute`). It sends the frame to a
QUIC-mode agent with no change, on the shard of its flow.

### QUIC and PSP bridge

The relay connects QUIC-mode and PSP-mode agents. It opens and seals only
this traffic; packets between two PSP-mode agents keep their end-to-end SA.

- Relay SAs: in PSP mode, the relay sends a rekey (`KeysRequest` with
  `OfferSAs`) right after `Config`, and a new one before the SAs expire. The
  agent seals packets for QUIC-mode agents with them and sends them to the
  relay. The relay checks the VNI, the inner source, the replay window and
  the SPI row, and sends the inner packet as a data frame. The VNI word of the
  frame is the VNI word of the PSP packet.
- Agent SAs: a PSP-mode agent gives the relay its own SAs with `Rekey`. The
  relay seals the data frames from QUIC-mode agents with them.

A relay SA has an SPI row from the agent to the relay, so the source address
check and the meter of the row apply. The relay does not offer an SPI that is
in a row of the agent.

## Calls

Each call uses one bidirectional QUIC stream. Either side can open a stream;
the side that opens it is the caller.

```
caller -> called:  0x01 0x01  frame(CallHeader)  frame(message)*  FIN
called -> caller:  frame(message)*  frame(Status)  FIN
frame:             kind (1 B) | length (uvarint, at most 5 B) | protobuf
kind:              0x01 CallHeader, 0x02 message, 0x03 Status
```

- `0x01 0x01` is the stream type (call) and the version.
- `CallHeader{method, timeout_ns, metadata}`: `method` is the full name, for
  example `/apoxy.vpc.datapath.v1.Relay/Attach`. `timeout_ns` is the time
  left before the deadline of the caller; 0 is no deadline.
- `Status{code, message}` uses the gRPC code numbers; 0 is OK. The messages are
  in `pkg/vpc/rpc/internal/wirepb/wire.proto`.
- A unary call has one message in each direction. A client-stream call sends
  messages until FIN and gets one message.
- Default limits: 16 KiB for a header or status frame, 4 MiB for a message.
- Cancel is RESET_STREAM and STOP_SENDING with a stream error code: `0x0` no
  error, `0x1` canceled, `0x2` deadline exceeded, `0x3` protocol error, `0x4`
  unsupported stream type or version.

## Messages

A VPC is always a `VPCRef{project_id, vpc_uid, network_id}`, never a name.
Addresses and prefixes are text (`fd61::1`, `10.0.0.0/8`, `host:port`).

### Relay (`apoxy-vpc/2`)

| Method          | Kind  | Messages |
|-----------------|-------|----------|
| `Session`       | bidi  | Agent: `Hello{mode}`, then `Ack{rev}` and `Status` (ICV failures). Relay: `Welcome` (reflexive address), `Config`, in PSP mode a rekey with relay SAs, then `RouteDelta{rev}`, `NoRoute`, rekey (`KeysRequest`), `Config`, `Drain`. |
| `Attach`        | unary | `AttachRequest{vpc, name, labels, routes}` -> `AttachResponse{attachment_id, grant}` |
| `Rekey`         | unary | `KeysRequest` -> `KeysResponse`: SAs for traffic from the relay to the agent. Errors: `FailedPrecondition` (no `Session` call in PSP mode), `InvalidArgument` (an SA VNI is not the network ID). |
| `ResolvePeer`   | unary | `{vpc, address}` -> `{reach: local, trunk or visit; home_relay; p2p}`. Errors: `NotFound`, `PermissionDenied`. |
| `RegisterSPI`   | unary | `{vpc, destination, spis, expires_in}` -> `Empty` |
| `UnregisterSPI` | unary | `{vpc, spis}` -> `Empty` |

`Attach` returns an `AttachmentGrant`: the claims, the signature of the relay
TLS key, and the relay cert chain (leaf first). A peer accepts it only if the
leaf chains through the rest of the chain to the roots that agents dial relays
with, the leaf names `relay_id` (a DNS name, for example the dial host name of
the relay), the leaf key made the signature, and `not_after` has not passed.

A connection has one `Session` call and lives as long as that call. A relay
closes a connection with a `RelayCloseCode`: `CERT` (the agent cert failed a
check; get a new cert before the next dial) or `DRAIN` (move to another
relay).

In QUIC mode an agent can add up to 3 shards: extra connections from the same
socket that carry data datagrams. Each one sends
`Hello{shard: {attachment_id, index}}` as its first `Session` message, gets
`Welcome`, and makes no other call. The relay refuses the join if the index is
not from 1 to 3 (`InvalidArgument`), if no open session has the attachment
(`NotFound`), if that session has another agent identity (`PermissionDenied`),
or if the connection already has a `Session` call, routes or SPI rows
(`FailedPrecondition`). A new shard with the same index replaces the old one.
A shard closes when its owner session closes.

The relay accepts an agent cert only if it chains to the agent CA, its SAN is
an agent ID, and the agent is not revoked in its VPC. It checks in the TLS
handshake and again for open sessions when the trust data changes, and closes
a session at the NotAfter of its cert. Each call must name the VPC in the
cert.

The relay takes the sender of an SPI row from the authenticated session, never
from packet data. A row ends at `UnregisterSPI`, at expiry, after 5 minutes
with no traffic, when either session closes, or when Permit stops allowing it.

### Peer (`apoxy-peer/1`)

| Method  | Kind          | Messages |
|---------|---------------|----------|
| `Open`  | unary         | Dialer and listener each send `{grant, instance, mode, p2p}`. First call on a session. |
| `Keys`  | unary         | The receiver sends `KeysRequest`: `OfferSAs`, `RekeySA` or `RevokeSA`. `KeysResponse` lists SPIs that the sender refuses. |
| `Paths` | client stream | `Candidates{round, candidates, mtu}`; each agent calls it. |

Each side accepts the other only if the peer cert chains to the VPC agent CA
and names the same project and VPC, the grant passes the checks above, is for
the same VPC, and names the SPIFFE ID of the peer cert, and the mode is `PSP`.
If not, it closes the session with `BAD_GRANT`. When both agents dial (an
open session in the other role with the same `instance`), the session that
the agent with the lower SPIFFE ID dialed stays, and the other closes with
`DUPLICATE`. A new `instance` replaces the open session.

The agent that receives `Keys` sends with those SAs. It registers their SPIs at
its relay before it applies them, and unregisters them after a revoke.

### Mesh (`apoxy-mesh/1`)

| Method      | Kind          | Messages |
|-------------|---------------|----------|
| `Presence`  | client stream | `PresenceUpdate` of the attachments of the caller. |
| `SPIRows`   | client stream | `SPIRowUpdate`: SPI rows for receivers on the called relay. |
| `TrunkKeys` | unary         | `KeysRequest` -> `KeysResponse` for the trunk SA. |

## JSON debug handler

`rpc.JSONHandler(mux)` serves the same handlers over HTTP with protojson. The
request body holds one or more JSON messages; the response has one message on
each line. Mount it on a loopback address only.

```
curl -d '{"vpc":{"project_id":"p-1","vpc_uid":"u-1","network_id":658188},"address":"fd61:a0b:c00:2::9"}' \
  http://127.0.0.1:8081/apoxy.vpc.datapath.v1.Relay/ResolvePeer
```
