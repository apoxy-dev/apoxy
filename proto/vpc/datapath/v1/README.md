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
relay itself are opened (see "QUIC and PSP bridge"). A relay socket also
carries the trunk packets of the other relays of its mesh (see "Trunk").

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

### Trunk

Two relays of a mesh have trunk SAs for the packets between them. A trunk SA
is a PSP SA with VNI 0, and the VNI field of its packets carries a tag. Each
relay makes the SAs for the packets that it receives, and gives them to the
other relay with `TrunkKeys`. A trunk has two SA lanes. Lane 0 has no replay
window and accepts only a payload that is a whole PSP packet. Lane 1 has a
replay window.

```
trunk packet:    PSP header and VC, with the tag (24 bits) in the VNI field | payload
tag 0:           a message of the relay itself, on lane 1
message:         type (1 B) | run ID (8 B) | zero padding
type:            0x01 full-size probe, 0x02 answer
```

A trunk packet whose payload is a PSP packet or a message has the next header
value 63, so its first byte is `0x3f`. A relay drops a trunk packet with
another tag. A relay accepts a trunk packet only from the address of its mesh
session with the other relay, and only with an SA that it gave to that relay.

On each new session with a relay at revision 5 or later, a relay offers new
SAs for the two lanes (`OfferSAs`). It sends new SAs before they expire
(`RekeySA`), as for the relay SAs of an agent. The called relay returns in
`refused_spis` the SPIs that it holds from another receiver, and the caller
offers new SAs for their lanes. After a call that failed, the caller waits as
before a dial (200 ms, doubling to 10 s, each with up to 50% more) and offers
new SAs for the two lanes. `Unimplemented` tells that the called relay has no
trunk, and the caller makes no more calls on that session. The SAs stay while
the other relay is up, so also in the 3 s after the session ended. When the
other relay is down, a relay deletes the SAs of the two directions.

When each relay gave its SAs on a session, each relay sends a full-size probe:
a message of 1412 B, so that the UDP payload is 1452 B, the largest that a
relay reads. The other relay answers with a message of the same size and run
ID. It answers at most 10 probes each second. A probe run sends up to 3
packets 300 ms apart. If no answer comes in 1 s, the relay has the trunk as
limited to an inner MTU of 1280, and it starts a new run each 30 s until one
passes. After a run that passes, the trunk carries a PSP packet with an inner
MTU of 1372. Before the first result, the limit of 1280 applies.

A relay sends the PSP packets of an agent to a receiver on another relay in
trunk packets. `RegisterSPI` for an address of a route of another relay makes
a row to the trunk of that relay. The relay needs a lane 0 SA of that relay,
and the session of the caller needs a sender tag, which it has from its first
attachment. If not, the call returns `NotFound`, as for an address with no
route. The relay applies the source address check, the meter of the row and
the tunnel limit to each packet of the row, as for a row to one of its own
sessions, and it does not open the packet. It seals the whole PSP packet with
the lane 0 SA, with the sender tag of the session of the sender in the VNI
field, and sends the trunk packet from its own port to the relay socket of the
other relay. It drops a PSP packet with an inner packet above the inner MTU of
the trunk, and it does not send the packet in parts. The XDP program has no
such row. The relay gives each such row to the other relay with `SPIRows` (see
"Mesh").

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
| `Session`       | bidi  | Agent: `Hello{mode, fallback_reason, spare, version, name, local_routes_only}`, then `Ack{rev}` and `Status` (ICV failures; the first one after `Config` also has the time to connect). Relay: `Welcome` (reflexive address, lane port limit, version), `Config`, in PSP mode a rekey with relay SAs, then `RouteDelta{rev}`, `NoRoute`, rekey (`KeysRequest`), `Config`, `Drain`, and in PSP mode `RxReport` (only the last one waits). |
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
A row to a receiver on another relay ends also when the route to its address
goes away, and when the relay has no lane 0 trunk SA of the other relay.

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
| `Presence`  | client stream | `PresenceUpdate`: the full set of the attachments of the caller, then each change. One call on a session. |
| `SPIRows`   | client stream | `SPIRowUpdate`: the SPI rows of the senders on the caller for receivers on the called relay. A row with a new end time comes again, and a row that ended comes with `removed`. One call on a session. |
| `TrunkKeys` | unary         | `KeysRequest` -> `KeysResponse`: trunk SAs for packets from the called relay to the caller (see "Trunk"). Errors: `Unimplemented` (the called relay serves no VPC relay sessions), `FailedPrecondition` (the caller is below revision 5, or the session is not the open session of a member), `InvalidArgument` (an SA VNI is not 0, or an SA lane is not 0 or 1). |

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

A relay tells each other relay of its attachments. On each new session with a
relay at revision 4 or later, it opens one `Presence` call. It first sends the
full set: an entry for each attachment that it has, in one or more
`PresenceUpdate` messages, with `end_of_full_set` in the last of them. Then it
sends each change: an entry for a new attachment, and an entry with `gone` for
an attachment that ended. An attachment does not change between these two
entries. A session that replaces an older one gets the full set again. A relay
at revision 3 gets no `Presence` call, and its session stays open.

An entry has the VPC, the attachment ID, the prefixes (the addresses and the
advertised routes), the SPIFFE ID and the `Hello.name` of the agent, and the
sender tag. The sending relay gives the sender tag, a number from 1 to
2^24 - 1, to the session of the agent at the first attachment of the session.
All attachments of one session have the same tag, and no other session of the
sending relay has it at the same time. The session keeps its tag until it
ends. The relay gives a tag again only after all the other tags. `generation`
is the time of the change in Unix milliseconds: the attach, or the end for a
`gone` entry. A relay sends each generation one time: when the clock is not
above the last generation, the next one is the last one plus 1. For one
attachment ID, the entry with the higher generation wins.

The called relay keeps the entries of each member. It ignores an entry with a
generation below the one that it has for the attachment ID, and a `gone` entry
for an attachment that it does not have. It refuses an entry with no
attachment ID, with an ID of more than 128 bytes or with no generation. It
also refuses an entry without `gone` that has no VPC, a network ID above 24
bits, a subject that is not an agent ID of that VPC, a tag out of range or a
prefix that does not parse. A refused entry does not end the call. A second
`Presence` call on a session gets `FailedPrecondition`. The entries of a
member stay after its session ends. The relay drops them when the member
closes with `RESTART` or leaves the member set.

A relay makes routes from the entries that it keeps. An entry gives a route
for each of its prefixes in its VPC, with the attachment ID as the origin,
when two conditions are true: an agent of the VPC has sent `Hello` to this
relay, and the network ID of the entry is the network ID of the VPC on this
relay. An entry with another network ID gets one warning and no route. The
rules for one prefix are:

- An attachment of this relay keeps the prefix, and it takes the prefix from
  an entry.
- When more than one entry lists the prefix, the entry with the highest
  generation gets it. For equal generations, the entry of the relay with the
  lower name gets it, then the entry with the lower attachment ID.
- When the attachment that has the prefix ends, the next entry gets it.

The relay sends these routes in `RouteDelta`, as it sends its own, to each
session at revision 6 or later whose `Hello` has no `local_routes_only`. A
session gets no route of an attachment of its own agent on another relay: the
rule of `Hello.name` applies to the SPIFFE ID and the agent name of the entry.
The route goes away with its entry: at a `gone` entry, and when the relay
drops the entries of a member.

A relay tells each other relay of the SPI rows that it has for receivers on
that relay (see "Trunk"). It opens one `SPIRows` call on a mesh session, at the
first such row. An `SPIRow` has the VPC, the sender tag of the session of the
sender on the calling relay, the SPI, the overlay address of the receiver and
`expires_in`, the time that the row has left. The sender tag and the SPI name
the row. The calling relay sends a row when `RegisterSPI` makes it, and again
with the new `expires_in` at each later `RegisterSPI` for it. It sends the row
with `removed`, and with no address and no `expires_in`, when the row ends on
the calling relay or goes to a receiver that is not on the called relay. The
rows of one change go in one or more messages of at most 256 rows.

`RegisterSPI` does not wait for the called relay, so the first packets of a
row can come before the row. On a new session, the calling relay sends each
row that it has for the called relay again. It does not send the rows that
ended while it had no session, so the called relay ends those by
`expires_in`. If the call fails, the calling relay makes no new call on that
session, and it keeps its rows.

When the other relay is down, a relay deletes the trunk SAs, so the packets
of its rows to that relay drop at once. Each second the relay ends the rows
to a relay of which it has no lane 0 SA. After the other relay is up again,
the next `RegisterSPI` of the agent makes the row again.

At this revision a relay answers `Unimplemented` to `SPIRows`, and it drops a
trunk packet with a sender tag, so no packet of an agent arrives through
another relay. `ResolvePeer` returns `NotFound` for an address of a route of
another relay. The relay drops a data frame, a peer frame or a PSP packet that
it opens for such an address, and sends `NoRoute`.

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
| 4 | `Presence.subject`, `agent_name` and `sender_tag`. `PresenceUpdate.end_of_full_set`. | No duty. | No duty. | Opens one `Presence` call on each mesh session with a relay at revision 4 or later: the full set of its attachments with the end mark, then each change. Opens none with a relay at revision 3, and keeps that session. Keeps the entries that each member sends, and drops them when the member closes with `RESTART` or leaves the member set. |
| 5 | `Mesh.TrunkKeys` and the trunk SAs. The trunk packet with tag 0: the full-size probe and its answer. | No duty. | No duty. | With a relay at revision 5 or later: offers trunk SAs on each new mesh session and before they expire, applies the trunk SAs of the other relay, probes the path at full size, and answers the probes of the other relay. Makes no `TrunkKeys` call to a relay below revision 5, refuses its call with `FailedPrecondition`, and keeps that session. Deletes the trunk SAs of a relay that is down. |
| 6 | `Hello.local_routes_only`. Routes of the attachments of other relays in `RouteDelta`. | Sends `local_routes_only` when its config has the option. Without it, gets the routes of the attachments of other relays from a relay at revision 6 or later. | Sends `local_routes_only`, because it has one session for each relay. | Makes a route for each prefix of the entries of the other relays. Sends these routes to a session at revision 6 or later that did not set `local_routes_only`, and to no other session. Answers `NotFound` to `ResolvePeer` for an address of such a route, and sends `NoRoute` for a packet to it that it opens. |

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
