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

### Data mode

`Hello.mode` sets the data mode of a session, and it does not change. An agent
in auto mode first sends path probes for 1280 B inner packets to the relay,
from its PSP socket. If no reply comes in 1 s, it opens the session in QUIC
mode with `fallback_reason` `PROBE_TIMEOUT`. In that mode it probes again with
backoff (30 s, doubling to 10 min). After two probes in a row pass, 5 s apart,
it opens a new session, which probes again. If the new session is in PSP mode,
the agent moves to it and closes the old one, as at a cert renew. An agent
with QUIC mode in its config sends `CONFIG` and does not probe.

### Spare sessions

An agent keeps up to two more sessions, each on another relay, with
`Hello.spare` set. A spare session gets `Config`, routes and `Drain` but
holds no attachment. When the attached session ends or drains, the agent
sends `Attach` on a spare, so the move needs no new handshake.

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

### Circuit breaker

A sender of data has a breaker (RFC 8084) for each PSP receiver, and one for
its QUIC data frames. A receiver reports the counters of its SAs in `RxReport`:
the packets that it accepted and the highest sequence number. An agent sends
them to its peers on `Reports` every 500 ms, and a relay sends them for its
relay SAs on `Session` each second, both only when they change. The loss of an
interval of 1 s or more is 1 - (change of packets) / (change of seq), so drops
at a relay meter count. For data frames, the loss is the lost 1-RTT packets of
the relay connections divided by the data frames sent.

The breaker trips when the loss is 20% or more in 3 intervals in a row that
each expect 100 packets or more. It then limits the send rate to half of the
rate that arrived, at least 1 Mbit/s. A trip while limited halves the limit
again. The limit ends 30 s after the last trip. The limit does not delay
packets: it drops a packet when the bytes over the limit are more than 2 ms at
the limit rate.

Agents and relays send all packets as Not-ECT, also in QUIC mode, so that the
network drops packets and does not mark them.

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
| `Session`       | bidi  | Agent: `Hello{mode, fallback_reason, spare, version, name}`, then `Ack{rev}` and `Status` (ICV failures; the first one after `Config` also has the time to connect). Relay: `Welcome` (reflexive address, lane port limit, version), `Config`, in PSP mode a rekey with relay SAs, then `RouteDelta{rev}`, `NoRoute`, rekey (`KeysRequest`), `Config`, `Drain`, and in PSP mode `RxReport` (only the last one waits). |
| `Attach`        | unary | `AttachRequest{vpc, name, labels, routes}` -> `AttachResponse{attachment_id, grant}` |
| `Rekey`         | unary | `KeysRequest` -> `KeysResponse`: SAs for traffic from the relay to the agent. Errors: `FailedPrecondition` (no `Session` call in PSP mode), `InvalidArgument` (an SA VNI is not the network ID). |
| `ResolvePeer`   | unary | `{vpc, address}` -> `{reach: local, trunk or visit; home_relay; p2p; subject; attachment_ids}`. Errors: `NotFound`, `PermissionDenied`. |
| `RegisterSPI`   | unary | `{vpc, destination, spis, expires_in, lanes, sa_lanes}` -> `Empty`. `lanes` gives the source of each SPI: 0 is the session address, i is port i of `RegisterLanes`. `sa_lanes` gives the SA lane of each SPI at the receiver. |
| `UnregisterSPI` | unary | `{vpc, spis}` -> `Empty` |
| `RegisterLanes` | unary | `{ports, receive}` -> `Empty`: replaces the lane ports of the session. `receive` tells that the agent reads them. Errors: `InvalidArgument` (more ports than `Welcome.max_lanes`, port 0, the session port, a repeated port), `AlreadyExists` (a port is a source of another agent), `FailedPrecondition`. |

`Attach` returns an `AttachmentGrant`: the claims, the signature of the relay
TLS key, and the relay cert chain (leaf first). A peer accepts it only if the
leaf chains through the rest of the chain to the roots that agents dial relays
with, the leaf names `relay_id` (a DNS name, for example the dial host name of
the relay), the leaf key made the signature, `min_revision` is not above the
revision of the peer, and `not_after` has not passed.

Many agents can have one SPIFFE ID. `Hello.name` is the name of the base
attachment of the agent, and it tells the agents of one SPIFFE ID apart. Two
sessions are of one agent when they have one SPIFFE ID and one name. A session
with no name is of the same agent as each session of its SPIFFE ID. The relay
uses this rule in three places:

- An advertised route moves to the newest attachment of the same agent that
  lists it. An `Attach` with an advertised route of another agent gets
  `AlreadyExists`.
- A session gets no routes of its own agent in `RouteDelta`. It gets the
  routes of the other agents of its SPIFFE ID.
- `ResolvePeer` gives the attachments of the session that has the address, so
  that the caller knows if it has a peer session with that agent.

All sessions of one SPIFFE ID can send from the routes of that SPIFFE ID.

A connection has one `Session` call and lives as long as that call. A relay
closes a connection with a `RelayCloseCode`: `CERT` (the agent cert failed a
check; get a new cert before the next dial), `DRAIN` (move to another relay)
or `UPGRADE` (the agent revision is below the minimum of the relay; see
"Revisions").

In QUIC mode an agent can add up to 3 shards: extra connections from the same
socket that carry data datagrams. Each one sends
`Hello{shard: {attachment_id, index}, version}` as its first `Session`
message, gets `Welcome`, and makes no other call. The relay refuses the join
if the index is not from 1 to 3 (`InvalidArgument`), if no open session has
the attachment (`NotFound`), if that session has another agent identity
(`PermissionDenied`), or if the connection already has a `Session` call,
routes or SPI rows (`FailedPrecondition`). A new shard with the same index
replaces the old one.
A shard closes when its owner session closes.

The relay accepts an agent cert only if it chains to the agent CA, its SAN is
an agent ID, and the agent is not revoked in its VPC. It checks in the TLS
handshake and again for open sessions when the trust data changes, and closes
a session at the NotAfter of its cert. Each call must name the VPC in the
cert.

The relay takes the sender of an SPI row from the authenticated session, never
from packet data. A row ends at `UnregisterSPI`, at expiry, after 5 minutes
with no traffic, when either session closes, or when Permit stops allowing it.

An agent sends each SA lane from its own UDP port, so that the lanes use more
NIC queues. The relay forwards PSP packets from the lane ports of a session as
from the session. A lane port is at the IP address of the session, and it is
free or a lane port of another session of the same agent. The lane ports go
away when the session closes, moves to a new address or joins as a shard. An
agent registers lane ports only when `Welcome.max_lanes` is not 0 and the
reflexive port is its local port.

When a receiver registers its lane ports with `receive`, the relay sends the
PSP packets of SA lane i to lane port i mod (n + 1) of the receiver, where n is
its lane port count and 0 is the session address. The relay sends from its own
port. It uses a lane port only after a keepalive from that port: the agent sends
the one byte 0x03 from each lane port to the relay after `RegisterLanes`, then
every 5 s. The relay forwards no keepalive. Until the first keepalive, and for
a receiver with no `receive`, all SA lanes go to the session address.

### Peer (`apoxy-peer/1`)

| Method    | Kind          | Messages |
|-----------|---------------|----------|
| `Open`    | unary         | Dialer and listener each send `{grant, instance, mode, p2p, lanes, version}`. First call on a session. `lanes` is the send lanes of the caller: the other agent offers it that many SAs. |
| `Keys`    | unary         | The receiver sends `KeysRequest`: `OfferSAs`, `RekeySA` or `RevokeSA`. `KeysResponse` lists SPIs that the sender refuses. |
| `Paths`   | client stream | `Candidates{round, candidates, mtu}`; each agent calls it. |
| `Reports` | client stream | `RxReport{sas}` every 500 ms when it changes: the receive counters of the SAs that the peer sends with. |

Each side accepts the other only if the peer cert chains to the VPC agent CA
and names the same project and VPC, the grant passes the checks above, is for
the same VPC, and names the SPIFFE ID of the peer cert, and the mode is `PSP`
or `QUIC`. If not, it closes the session with `BAD_GRANT`. If the revision of
the other agent is below its minimum, it closes the session with `UPGRADE`
(see "Revisions"). When both agents
dial (an open session in the other role with the same SPIFFE ID and the same
`instance`), the session that the first agent dialed stays, and the other
closes with `DUPLICATE`. The first agent has the lower SPIFFE ID, or the lower
`instance` when the two agents have one SPIFFE ID.

Many agents can have one SPIFFE ID, so an agent keeps one session for each
`instance` of a SPIFFE ID. A new session replaces an open session of the same
SPIFFE ID with another `instance` only when its grant has an address of that
session.

If one of the agents is in `QUIC` mode, data between them goes through the
relay, which bridges PSP and QUIC data frames. The pair does not call `Keys`,
and both sessions of a crossed dial stay.

The agent that receives `Keys` sends with those SAs. It registers their SPIs at
its relay before it applies them, and unregisters them after a revoke.

### Mesh (`apoxy-mesh/1`)

| Method      | Kind          | Messages |
|-------------|---------------|----------|
| `Open`      | unary         | Dialer and listener each send `{version, name, relay}`. First call on a session. |
| `Presence`  | client stream | `PresenceUpdate` of the attachments of the caller. |
| `SPIRows`   | client stream | `SPIRowUpdate`: SPI rows for receivers on the called relay. |
| `TrunkKeys` | unary         | `KeysRequest` -> `KeysResponse` for the trunk SA. |

A member of a mesh is one relay process, and its relay name identifies it.
Many relays can have one relay ID, so the mesh does not use the ID to tell
members apart. Two members have one session. The relay with the lower name
dials, from its listening socket, and calls `Open`. The other relay refuses a
session that the relay with the higher name dialed. A new session of the two
relays replaces the session before it. The other calls of a session are valid
only after `Open` passes.

A relay closes a session with a `MeshCloseCode`: `NOT_MEMBER` (the name of the
other relay is not in its member set, is not the name that it dialed, or the
certificate failed the check of the relay host), `UPGRADE` (the revision of the
other relay is below its minimum, or below 3, the first revision with `Open`;
see "Revisions") or `RESTART` (the relay stops on purpose, and its attachments
are gone).

Both relays send a QUIC keep-alive each second and use an idle timeout of 5 s,
so a relay sees a lost path 5 s to 6 s after the last packet of the other
relay. After a session ends, the relay that dials waits 200 ms and dials
again. The wait doubles after each failed dial, up to 10 s, and each wait gets
up to 50% more at random. A relay has the other relay as down 3 s after the
session ended, if no new session opened. After `RESTART` it is down at once.

## Revisions

Agents run on customer hosts for months, and relays change more often, so the
two sides of a session have different ages. One number, the protocol revision,
covers the `Relay`, `Peer` and `Mesh` services and the packet formats. The Go
constants `Revision` and `MinRevision` are in `version.go`.

The first message of a session and its answer carry a
`Version{revision, min_revision, build}`: `Hello` and `Welcome` on a relay
session, `OpenRequest` and `OpenResponse` on a peer session. A build from
before revisions sends no `Version`, and that reads as revision 0. `build` is
only for logs and metrics. On a mesh session, `MeshOpenRequest` and
`MeshOpenResponse` carry it.

| Revision | Change | Agent | VTEP | Relay |
|----------|--------|-------|------|-------|
| 0 | The protocol before revisions. | Sends no `Version`. | Sends no `Version`. | Sends no `Version`. |
| 1 | `Version` in `Hello`, `Welcome` and `Open`. `GrantClaims.min_revision`. The `UPGRADE` close codes. | Sends its `Version` in `Hello` and in `Open`. Stops the dial loop when a relay closes with `UPGRADE` and no other relay takes it, and tells the user to upgrade. Dials the next relay when a relay is below its minimum. Closes a peer session below its minimum with `UPGRADE`. Refuses a grant with a `min_revision` above its revision. Keeps the session when a call returns `Unimplemented`. | The duties of the agent on the relay session. | Sends its `Version` in `Welcome`. Closes a session below its minimum with `UPGRADE`. Counts the sessions by revision and build. |
| 2 | `Hello.name`. `ResolvePeerResponse.attachment_ids`. | Sends the name of its base attachment in `Hello`. With a relay at revision 2, waits for the grant of an address only when `attachment_ids` has an attachment of an open peer session. With an older relay, waits when the subject is that of an open peer session. | The duties of the agent on the relay session. | Has two sessions with one SPIFFE ID as one agent only when their names are equal or one has no name. Sends `attachment_ids` in `ResolvePeer`. |
| 3 | `Mesh.Open` with the `Version`, the relay name and the `RelayRef` of each relay. The `MeshCloseCode` values. | No duty. | No duty. | Calls `Open` first on a mesh session that it dialed, and answers it on a session that it accepted. Closes a mesh session with a relay below its minimum with `UPGRADE`, and with a relay that is not a member with `NOT_MEMBER`. Closes its mesh sessions with `RESTART` when it stops. |

### Minimum revision

Each side has a minimum for the revision of the other side. It is 0 now.

- A relay closes a session below its minimum with the `RelayCloseCode`
  `UPGRADE`, and the close reason gives the minimum. When no other relay takes
  the agent, the agent stops its dial loop and returns an error that tells the
  user to upgrade.
- An agent that finds a relay below its minimum closes the session and dials
  the next relay.
- On a peer session, the agent that finds the other agent below its minimum
  closes the session with the `PeerCloseCode` `UPGRADE`. The relay sessions
  stay.
- A verifier refuses a grant with a `min_revision` above its own revision,
  because it does not know all the claims that limit the grant.
- A build from before revision 1 does not know `UPGRADE`. It sees a normal
  close and dials again with backoff.
- The relay counts the sessions by revision and build of the agent
  (`apoxy_vpc_relay_session_versions_total`). The counts show how many
  sessions a higher minimum closes.

### Rules for a change

- A change only adds: new fields, oneof cases, messages, methods and enum
  values. No number, type or name changes. A removed field or enum value
  becomes `reserved`, by number and by name. The zero value of a new field
  means the old behavior.
- Each change to the proto files or to a packet format adds 1 to `Revision`
  and one line to the table: the number, the change and the duty of each role.
  A role with no duty for a revision has nothing to implement. It only must
  not break on the new messages.
- The revision is cumulative: a side at revision N obeys each duty of its role
  up to N.
- A side uses a new behavior only when the revision of the other side shows
  it. A packet carries no negotiation, so a side sends a new packet format
  only after the control channel shows that the other side reads it.
- The first message offers, and the answer selects. `Hello` has only values
  that the oldest supported relay accepts. A new choice is a new field of
  `Hello`, never a new value of an old field.
- A caller that gets `Unimplemented` treats the call as not supported and
  keeps the session.
- The revision tells what the code can do, not what is turned on. An option
  that depends on the config or on the host keeps a typed field, such as
  `Welcome.max_lanes`, and its zero value means off.
- A new ALPN name is only for a change that these rules cannot express: new
  stream framing, a new first exchange or a new datagram header.
- Relays deploy before an agent release. A relay rollback is safe: the agent
  sees the lower revision in the next `Welcome` and stops the newer behavior.
- When the minimum passes revision N, the code for the revisions below N goes
  away in one change, and the fields that only they used become `reserved`.

The steps for one change:

1. Add the fields, messages or methods. Add the line to the table, and add 1
   to `Revision`.
2. Use the new behavior only after a check of the revision of the other side.
3. Add test cases for the other side at the old revision and at the new one.
4. Deploy the relays, and then release the agents.
5. After the minimum passes the revision, remove the old path and reserve its
   fields.

### Descriptor lock

`TestDescriptorLock` compares the descriptors of the proto files with
`testdata/descriptors.lock.json`, the copy from the last release. It fails
when a field changes its number, type, name or cardinality (singular,
optional, repeated or in a oneof), when a field or an enum value goes away
without `reserved` for its number and its name, when an enum value changes its
number or name, when a message, an enum, a service or a method goes away, and
when a method changes its input, its output or its streaming. A change that
only adds passes.

At each release, after the test passes, update the locked copy:

```
go test ./proto/vpc/datapath/v1 -run TestDescriptorLock -update
```

## JSON debug handler

`rpc.JSONHandler(mux)` serves the same handlers over HTTP with protojson. The
request body holds one or more JSON messages; the response has one message on
each line. Mount it on a loopback address only.

```
curl -d '{"vpc":{"project_id":"p-1","vpc_uid":"u-1","network_id":658188},"address":"fd61:a0b:c00:2::9"}' \
  http://127.0.0.1:8081/apoxy.vpc.datapath.v1.Relay/ResolvePeer
```
