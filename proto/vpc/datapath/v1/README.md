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
carries the packets of the other relays of its mesh: the PSP packets of their
agents and trunk packets (see "Trunk").

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
session routes the destination. For the last two it sends `NoRoute`. When a
session of another relay of the mesh routes the destination, the relay sends
the frame to that relay (see "Mesh datagrams").

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
QUIC-mode agent with no change, on the shard of its flow. When a session of
another relay of the mesh routes the inner destination, the relay sends the
inner packet to that relay (see "Trunk").

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

When the two agents are on two relays of a mesh, the relay of the sender opens
the data frame or the PSP packet, and the relay of the receiver sends the
inner packet to the receiver. The inner packet goes between them in a trunk
packet (see "Trunk").

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

Two relays of a mesh send two kinds of packets to the relay socket of each
other. The PSP packet of an agent for a PSP-mode agent of the other relay goes
with no change: no relay opens it, and no relay seals it again. A clear inner
packet that a relay holds, and a message of the relay itself, go in a trunk
packet, which the relay seals with a trunk SA. Thus each packet between two
relays has the 40 B of PSP one time.

A trunk SA is a PSP SA with VNI 0, and the VNI field of its packets carries a
tag. Each relay makes the SAs for the trunk packets that it receives, and
gives them to the other relay with `TrunkKeys`. A trunk has one SA lane, and
its SAs have a replay window.

```
trunk packet:    PSP header and VC, with the tag (24 bits) in the VNI field | payload
tag 0:           a message of the relay itself
tag 1 and up:    a sender tag, with a clear inner packet of that sender
message:         type (1 B) | run ID (8 B) | zero padding
type:            0x01 full-size probe, 0x02 answer
```

A trunk packet with a message has the next header value 63, so its first byte
is `0x3f`. A trunk packet with a clear inner packet has the next header value
of that packet: 4 for IPv4 and 41 for IPv6. The PSP packet of an agent has the
same form, so only the SPI tells the two apart. A relay decides by the SPI of
each packet from the address of its mesh session with another relay:

1. The SPI is of a trunk SA that this relay gave to that relay: it opens the
   trunk packet.
2. The SPI is of a row that that relay gave in `SPIRows` (see "Mesh"): it
   sends the packet with no change to the receiver of the row.
3. Each other SPI: it drops the packet (`trunk_no_row`).

A relay does not use the SA or the row of one member for a packet from the
address of another member.

An SPI thus has one use for the packets from one relay to another. The relay
of the receiver cannot keep this rule: the SPIs of the rows come from agents.
The relay of the sender keeps it, because it has each row to the other relay
and each trunk SA that the other relay gave:

- `RegisterSPI` for an address of another relay returns `AlreadyExists` when
  another row to that relay has one of the SPIs, or when a trunk SA of that
  relay has it. The call then makes no row. The agent returns the SPIs of the
  key change in `refused_spis`, and its peer offers SAs with new SPIs, at most
  3 times for one key change.
- When the address of a row goes to a relay that has the SPI of the row in
  use, the row ends. The next `RegisterSPI` of the agent for the row returns
  `AlreadyExists`. The agent then closes the peer session, and its next packet
  opens a peer session with new SAs.
- `TrunkKeys` returns in `refused_spis` the SPI of an SA that a row to the
  caller has, and the caller offers an SA with a new SPI. In the time of that
  one call the caller has the SA, so it drops the packets of that row
  (`malformed`).
- An SPI of a trunk SA stays in use until the end time of the SA, also after
  the other relay revoked the SA and while that relay is down. That relay can
  open packets with an SA for some time after it replaced the SA.

A relay counts the rows that it refuses or ends for this rule in
`apoxy_vpc_relay_refused_rows_total`, with the `reason` `row` or `trunk_sa`.

On each new session with a relay at revision 13 or later, a relay offers a new
trunk SA (`OfferSAs`). It sends a new SA before the SA expires (`RekeySA`), as
for the relay SAs of an agent. The called relay returns in `refused_spis` the
SPIs that it holds from another receiver or in a row to the caller, and the
caller offers a new SA. After a call that failed, the caller waits as before a
dial (200 ms, doubling to 10 s, each with up to 50% more) and offers a new SA.
`Unimplemented` tells that the called relay has no trunk, and the caller makes
no more calls on that session. The SAs stay while the other relay is up, so
also in the 3 s after the session ended. When the other relay is down, a relay
deletes the SAs of the two directions.

A relay has no trunk with a relay below revision 13. It makes no `TrunkKeys`
call and no `SPIRows` call to that relay, refuses those calls of that relay
with `FailedPrecondition`, sends it no packet of a sender, and keeps the
session. No released relay had the trunk formats of the revisions 5, 8 and 9.

When each relay gave its SA on a session, each relay sends a full-size probe:
a message of 1412 B, so that the UDP payload is 1452 B, the largest that a
relay reads. The other relay answers with a message of the same size and run
ID. It answers at most 10 probes each second. A probe run sends up to 3
packets 300 ms apart. If no answer comes in 1 s, the relay has the trunk as
limited to an inner MTU of 1280, and it starts a new run each 30 s until one
passes. After a run that passes, the trunk carries an inner MTU of 1412.
Before the first result, the limit of 1280 applies. The limit is for the PSP
packets of the agents and for the clear inner packets: they use one path.

The largest MTU of a VPC network is also 1412. A relay gives an agent at most
1412 as the MTU of the network, also for a network object with a larger number
from before a check of its spec. The sizes on a path that carries 1500 B, with
an IPv6 header of 40 B and a UDP header of 8 B:

| Packet between two relays | PSP overhead | Largest inner packet | UDP payload |
|---------------------------|--------------|----------------------|-------------|
| PSP packet of an agent, with no change | 40 B, from the agent | 1412 B | 1452 B |
| Trunk packet with a clear inner packet | 40 B, from the relay of the sender | 1412 B | 1452 B |
| The two kinds, with no full-size probe that passed | 40 B | 1280 B | 1320 B |

`RegisterSPI` for an address of a route of another relay makes a row to that
relay. The session of the caller needs a sender tag, which it has from its
first attachment. If not, the call returns `NotFound`, as for an address with
no route. The call needs no trunk SA and does not wait for the other relay.
The relay applies the source address check, the meter of the row and the
tunnel limit to each packet of the row, as for a row to one of its own
sessions, and it does not open the packet. It sends the packet with no change
from its own port to the relay socket of the other relay. It drops a PSP
packet with an inner packet above the inner MTU of the trunk (`trunk_mtu`),
and it does not send the packet in parts. The relay gives each such row to the
other relay with `SPIRows` (see "Mesh").

The XDP program forwards the packets of such a row as it forwards the packets
of a row to an agent, with the relay socket of the other relay as the next
hop. The other relay knows this relay by the source address of a packet, and
the program sends from the address that the packet of the agent came to. So
the row is in the program only while the trunk has a full path and the
program has one address of that family, the address that the host sends from
to the other relay. In each other case the socket path sends the packets. The
program of the relay of the receiver has no row for a packet from another
relay, so its socket path gets each such packet.

The row stays while the relay has no session of the other relay, and the relay
drops the packets of the row in that time (`trunk_keys`). The sender gets a
`NoRoute` for such a packet only when it must visit the other relay (see
"Mesh"). When the other relay has a session again, from the same address or
from a new one, the row carries packets again with no call of the agent. It
needs no trunk SA.

The relay that gets the PSP packet of a row from another relay (rule 2) does
not open it. It drops the packet at the first of these checks that fails:

1. The packet has the form of a PSP packet with an IP packet in it
   (`malformed`).
2. The row of the SPI has not ended (`trunk_expired`).
3. An entry of the other relay has the sender tag of the row in the VPC of the
   row (`trunk_sender`). The rule of "Mesh datagrams" for the session of an
   entry applies, with the session that gave the row. That session does not
   have to be open.
4. Permit allows the destination of the row for the VPC and the SPIFFE ID of
   that entry (`trunk_permit`).
5. A session of this relay routes the destination of the row in that VPC
   (`trunk_not_local`). A relay sends no packet of a member to another member,
   so a PSP packet goes between relays one time at most.

Then it sends the PSP packet, with no change, from its own port to the address
of that session. It applies no meter and no tunnel limit, because the relay of
the sender applied them. It counts the packet and its inner bytes as sent to
the attachment of the destination. The relay does the checks 3 to 5 for each
packet, so a row that fails one of them carries packets again when the entry,
Permit or the route changes. It holds no packet: a packet that comes before
its row or before the entry of its sender drops. A relay counts each packet
that it drops on these paths in `apoxy_vpc_relay_dropped_packets_total`, with
a `reason` that starts with `trunk_`.

A relay does not authenticate the PSP packet of an agent that comes from
another relay, because it has no key of that packet. It takes the packet for
the source address of the member and the SPI of a row, as it takes the packet
of one of its own agents for the source address of the agent and the SPI of a
row. The exposure is thus the same as with one relay: a host that can send
from that address, and that knows an SPI, makes the relay send a packet to the
receiver of the row. The receiver drops it: the ICV of its SA fails, and the
replay window of its SA refuses a copy of a real packet.

A relay sends the clear inner packets that it holds to a receiver on another
relay in trunk packets. It holds the inner packet of a data frame of a
QUIC-mode session, and of a PSP packet that an agent sealed with a relay SA
(see "QUIC and PSP bridge"). The checks of the data frame or of the relay SA
come first. When Permit allows the inner destination and an attachment of
another relay has its route, the relay seals the inner packet with the trunk
SA of that relay, with the sender tag of the session of the sender in the VNI
field. It sends the trunk packet, which is 40 B longer than the inner packet,
from its own port to the relay socket of the other relay. It sends no
`NoRoute` for such a packet, because the address has a route. The one exception
is a sender that must visit the other relay (see "Mesh"). It drops the
inner packet, and counts the drop, in these cases:

- The relay has no session of the other relay at revision 13 or later, or no
  trunk SA of it (`trunk_keys`).
- The inner packet is above the inner MTU of the trunk (`trunk_mtu`). The
  relay does not send the packet in parts, and the agent gets no message for
  this drop.
- The session of the sender has no sender tag.

The tunnel limit applies to a data frame after these checks, so a frame that
the trunk does not carry takes nothing from it. For a PSP packet with a relay
SA, the meter of its row and the tunnel limit apply before them.

The relay that gets a trunk packet with a sender tag (rule 1) opens it. The
replay window of the SA drops a packet that the relay had before
(`trunk_replay`), and a payload that is no IP packet drops (`trunk_payload`):
a relay seals no PSP packet of an agent. The relay drops the inner packet at
the first of these checks that fails:

1. An entry of the other relay has the sender tag (`trunk_sender`). The rule
   of "Mesh datagrams" for the session of an entry applies, with the session
   on which this relay gave the SA of the trunk packet to the other relay.
   That session does not have to be open.
2. The route of the inner source address in the VPC of that entry is from
   that entry, as for a peer frame (`trunk_source`).
3. Permit allows the inner destination for the VPC and the SPIFFE ID of that
   entry (`trunk_permit`).
4. A session of this relay routes the inner destination in that VPC
   (`trunk_not_local`). An inner packet goes over one trunk at most.

Then it sends the inner packet as it sends the inner packet of a data frame
of one of its own sessions: in a data frame to a QUIC-mode agent, on the
shard of its flow, or sealed with the SA that a PSP-mode agent gave with
`Rekey`. The data frame has the network ID of the VPC and zero flags, because
a trunk packet has no VNI word. The inner packet drops when the session does
not take the data frame, and when the relay has no SA of the PSP-mode agent
(`trunk_not_sent`). The relay applies no tunnel limit, because the relay of
the sender applied it, and it counts the packet and its bytes as sent to the
attachment of the destination. The relay of the receiver does not know the
mode of the sender. Thus it also seals the inner packet of a PSP-mode sender
for a PSP-mode receiver, which a relay does not do for two of its own
sessions.

A relay also counts the packets of agents between it and each mesh member.
These metrics have one set of series for each member that the mesh has now,
and none for each agent. Their labels are `peer_relay`, the relay name of the
member, `peer_relay_id`, the last relay ID that the member gave (empty if it
gave none), and `direction`: `tx` to the member, `rx` from it.

- `apoxy_vpc_relay_trunk_packets_total` and `apoxy_vpc_relay_trunk_bytes_total`:
  the PSP packets of agents with no change and the trunk packets with a sender
  tag, and their UDP payload bytes. The `tx` counts include the packets that
  the XDP program sent. The `rx` counts have only the packets that the relay
  sent on. The probes and their answers do not count.
- `apoxy_vpc_relay_trunk_dropped_packets_total`, with the label `reason`:
  `trunk_mtu` and `trunk_keys` for `tx`, and `malformed` and the other
  `trunk_` reasons for `rx`.
- `apoxy_vpc_relay_mesh_rtt_seconds`: the smoothed RTT of the QUIC connection
  of the mesh session. A member with no session has no value.

### Mesh datagrams

QUIC DATAGRAM frames on a mesh session carry the peer frames between an agent
of one relay and an agent of the other relay. They need no trunk SA. The first
byte of a datagram is its type, so that other types can come later, and a
relay drops a datagram with a type that it does not know.

```
relay -> relay:  type (1 B) | sender tag (3 B) | dst address (16 B) | src address (16 B) | packet
type:            0x01 peer frame
```

The sender tag is the `sender_tag` of the `Presence` entries of the session
that sent the frame, with the high byte first. The addresses and the packet
are those of the frame of the agent. Both relays use a QUIC InitialPacketSize
of 1273 B or more on a mesh session, so that each packet of a peer session
fits in one datagram.

A relay sends a peer frame of an agent in this form when an attachment of
another relay has the route of the destination, and that relay is at revision
7 or later. The checks of "Relay datagrams" come first. The relay does not
split a frame. It drops a frame that does not fit in a datagram of the mesh
session, a frame for a relay with no open mesh session, and a frame for a
relay below revision 7. It sends no `NoRoute` for these frames, because the
address has a route. The one exception is a sender that must visit the other
relay (see "Mesh").

The relay that gets the datagram drops it at the first of these checks that
fails:

1. The datagram has the full header and the type `0x01`.
2. An entry of the other relay has the sender tag. The other relay sent the
   entry, or sent it again, in the `Presence` call of the session of the
   datagram, that session is open, and no later session of that relay has a
   `Presence` call. An entry from an older session does not count, because
   the other relay can have given its tag to another agent.
3. The route of the source address in the VPC of that entry is from that
   entry. This is the source check of "Relay datagrams" on the entries.
4. Permit allows the destination for the VPC and the SPIFFE ID of the entry.
5. A session of this relay routes the destination in that VPC. A relay sends
   no frame from a mesh session to another relay, so a frame goes over one
   mesh session at most.

Then it sends the frame to that session in the "relay -> agent" form. A relay
counts each frame that it drops on these paths in
`apoxy_vpc_relay_dropped_packets_total`, with a `reason` that starts with
`mesh_`.

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
| `ResolvePeer`   | unary | `{vpc, address}` -> `{reach: local, trunk or visit; p2p; subject; attachment_ids; home_relay}`. Errors: `NotFound`, `PermissionDenied`. |
| `RegisterSPI`   | unary | `{vpc, destination, spis, expires_in, lanes, sa_lanes}` -> `Empty`. `lanes` gives the source of each SPI: 0 is the session address, i is port i of `RegisterLanes`. `sa_lanes` gives the SA lane of each SPI at the receiver. Errors: `AlreadyExists` (the caller has an SPI in a row for another destination, another session on its socket has it, or the relay of the receiver has it in use: see "Trunk"). |
| `UnregisterSPI` | unary | `{vpc, spis}` -> `Empty` |
| `RegisterLanes` | unary | `{ports, receive}` -> `Empty`: replaces the lane ports of the session. `receive` tells that the agent reads them. Errors: `InvalidArgument` (more ports than `Welcome.max_lanes`, port 0, the session port, a repeated port), `AlreadyExists` (a port is a source of another agent), `FailedPrecondition`. |
| `Visit`         | unary | `{vpc, address, grant}` -> `Empty`: the session becomes a visitor with the prefix of the grant that has `address` (see below). Errors: `Unimplemented` (the relay has no mesh), `Unavailable` (the relay cannot read the relay roots), `PermissionDenied`, `FailedPrecondition`, `AlreadyExists`, `ResourceExhausted`. |

`Attach` returns an `AttachmentGrant`: the claims, the signature of the relay
TLS key, and the relay cert chain (leaf first). A peer accepts it only if the
leaf chains through the rest of the chain to the roots that agents dial relays
with, the leaf names `relay_id` (a DNS name, for example the dial host name of
the relay), the leaf key made the signature, `min_revision` is not above the
revision of the peer, and `not_after` has not passed.

A relay with a mesh refuses an `Attach` with more than 64 prefixes, the
addresses and the advertised routes together (`InvalidArgument`), because the
other relays refuse an entry with more prefixes (see "Mesh"). A relay with no
mesh has no such limit.

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

`ResolvePeer` tells how the relay reaches an address. Permit comes first: a
caller that Permit denies gets `PermissionDenied`, and does not learn if the
address exists. The answer is `REACH_LOCAL` with `p2p` when a session of this
relay has the route of the address. It is `REACH_TRUNK` when a session of
another relay of the mesh has the route and the caller can open a peer session
to it now (see "Mesh" for the conditions). The two answers have `subject`, the
SPIFFE ID of that session, and `attachment_ids`, its attachments. It is
`REACH_VISIT` with `home_relay` when the caller must attach to the relay of
the address as a visitor (see "Mesh" for the conditions). In each other case
the call returns `NotFound`.

`Visit` is for an agent whose relay has no path to the relay of a peer. The
agent opens one more session, to the relay of the peer, and calls `Visit` with
the grant of its attachment on its own relay (its home relay) and an address
of that grant. The session is then a visitor: the sessions of the visited
relay reach the prefix of the grant that has the address on that session. The
visitor keeps the address of its home relay. It gets no new address and no
attachment, and the visited relay does not send it in `Presence`. So no other
relay learns of the visit, and no route changes: a session of the visited
relay keeps the route that it has for the address, and gets no `RouteDelta`.

Of two agents whose relays have no path between them, the agent with the
lower overlay address visits first. The agent with the higher address waits
2 s for the peer session of that visit. Then it visits the relay of its peer
in the same way, if no peer session came, or at once if the peer refuses its
keys because the path of the visit carries no data. An agent that has a peer
session with the peer on its attached session, with the path up, does not
visit. When each agent visits the relay of the other, one peer session stays:
the one on the relay of the agent with the higher address, which is on the
visit of the lower address. Each agent refuses or closes the other one with
`PEER_CLOSE_CODE_DUPLICATE`, and ends the visit that no peer uses at its next
check.

The path of a peer session is down when the relay of the agent sends `NoRoute`
with `home_relay` for the address of the peer, and when the peer refuses the
keys of the agent because its visit carries no data. The session stays open.
A new peer session of the same agent replaces a session with the path down,
also when the rule for two dials keeps the old one. An agent that must refuse
a dial by that rule first asks its relay with `ResolvePeer`: on the answer
`REACH_VISIT` the path of the old session is down, and the new session
replaces it. A session with the path up keeps the rule for two dials.

The visited relay accepts the call only if all of these are true:

- The relay has a mesh (`Unimplemented`), and it can read the relay roots of
  the project of the caller (`Unavailable`).
- The grant passes the checks of a grant (see `Attach` above) with those
  roots: the cert chain, the signature, the name, `min_revision` and
  `not_after` (`PermissionDenied`).
- The VPC and the subject of the grant are those of the cert of the caller
  (`PermissionDenied`).
- `relay_id` of the grant is the relay ID that a member of the mesh gave in
  `Open` on its newest session, and that session did not close with `RESTART`
  (`PermissionDenied`). A grant names its relay itself. Without this check,
  the owner of any public server certificate in the VPC could sign a grant
  when the relay roots are the system roots.
- The address is in a prefix of `addresses` of the grant
  (`PermissionDenied`). That prefix is the prefix of the visit. The advertised
  routes of the attachment are not in the grant, so a visit does not have
  them.
- Permit allows the caller to reach the address (`PermissionDenied`).
- The session has a `Session` call with `local_routes_only`, it has and had
  no attachment, and it is not a visitor (`FailedPrecondition`). A visitor
  reaches no other relay, so it must not get the routes of other relays.
- The route of exactly that prefix is not of an attachment of the visited
  relay and not of another agent, and no other agent visits with the prefix
  (`AlreadyExists`). A grant lives as long as the agent cert, so it can be
  older than the owner that the address has now.
- The agent has fewer than 2 visitor sessions on the relay in the VPC
  (`ResourceExhausted`). A relay counts only its own sessions, so an agent
  can have 2 on each relay.

A member that is down keeps its relay ID, because a lost path to the home
relay is the usual cause of a visit. A member has no relay ID when it closed
with `RESTART`, when it left the member set, when it gave none in `Open`, and
when the visited relay had no mesh session with it since the visited relay
started. Many members can give one relay ID, and the visited relay cannot
tell them apart.

A visitor talks only with the attachments of the visited relay:

- A peer frame, a data frame and a PSP packet that the relay opens, from a
  session of the visited relay to an address of the visit prefix, go to the
  visitor session and not to the home relay. `RegisterSPI` for such an address
  makes a row to the visitor session. A longer route in the prefix keeps its
  addresses.
- The visitor sends peer frames and data frames from the addresses of its
  prefix, and calls `RegisterSPI`, only for an address of an attachment of
  the visited relay. For an address of another relay, or of another visitor,
  it gets the answer for an address with no route: `NoRoute`, or `NotFound`.
- Nothing of a visitor goes to another relay, and nothing of another relay
  goes to a visitor. A mesh datagram, a trunk packet and an SPI row of another
  relay use the routes, which do not have the visitor.
- A visitor session takes no attachment (`FailedPrecondition`), and no shard
  joins it.
- `ResolvePeer` does not know the visit. For the address of a visitor it
  gives the answer for the route of that address.

When one agent has two visitor sessions with one prefix, the newest session
gets the traffic, and the other session gets it when the newest ends. Thus an
agent can open the second session before it closes the first.

A visit ends when the session ends, when `not_after` of the grant passes (the
relay looks each second), and when an attachment of the visited relay or an
entry of another agent gets the route of exactly the visit prefix. From then
on, the sessions of the visited relay reach the address by its route again.
A visit does not end when the home relay is lost, stops or leaves the member
set, when its entry for the address goes away, or when the relay roots
change: the relay checked the grant at the call, and `not_after`, which is at
most the end of the agent cert, limits the visit. Permit applies to each
frame, packet and row of a visitor, as for each session.

The SPI rows of the sessions of the visited relay follow the visit at once.
At its start, each row to an address of the prefix goes to the visitor
session, and a row that was on the trunk ends on the home relay (`removed` in
`SPIRows`). At its end, each such row goes to the owner that the route gives
then: the entry of the home relay (the row goes in `SPIRows` again), an older
visitor session of the agent, or an attachment of the visited relay. A row
with no such owner ends.

A connection has one `Session` call and lives as long as that call. A relay
closes a connection with a `RelayCloseCode`: `CERT` (the agent cert failed a
check; get a new cert before the next dial), `DRAIN` (move to another relay)
or `UPGRADE` (the agent revision is below the minimum of the relay; see
"Revisions").

`Drain` tells an agent that the relay stops soon. From then on the relay
refuses each new connection with `DRAIN`, and it closes the sessions that are
left when the drain ends. `alternates` lists the relays that the agent can
move to, each as a `RelayRef{id, addresses}`: the other relays of the mesh
that have an open mesh session with the draining relay and gave agent
addresses in `Open`. The mesh has no measure of distance, so the list is in
the order of the relay names, and all agents get the same list. Two relays
that gave the same ID and addresses are one entry. A relay with no mesh sends
no alternates. A session that gets no routes of other relays (below revision
6, or with `local_routes_only`) gets none, as before the mesh: an agent with
`local_routes_only` has a session with each relay, so it must not move. A
relay in the list can drain at the same time. It then refuses the agent with
`DRAIN`, and the agent goes to the next address.

An agent that gets `Drain` on the session of its attachment moves the
attachment before that session ends. It first uses a spare session, and a
spare on a relay with the ID of an alternate goes first. With no spare, it
dials each address of each alternate in the order of the list, and it
attaches on the first relay that takes it. It closes the old session after
the new session has the attachment. With no alternate and no spare, it dials
the address of the draining relay again, which only a new relay process
answers. If that fails, it keeps the session until the relay closes it, and
then dials the relays that it knows.

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
goes away, and when its address goes to a relay that has its SPI in use (see
"Trunk"). It does not end when the relay has no session of the other relay.

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
`instance` when the two agents have one SPIFFE ID. An open session with the
path down does not stay by this rule: the new session replaces it (see `Visit`
in "Relay").

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
| `SPIRows`   | client stream | `SPIRowUpdate`: the SPI rows of the senders on the caller for receivers on the called relay. A row with a new end time comes again, and a row that ended comes with `removed`. One call on a session. Errors: `Unimplemented` (the called relay serves no VPC relay sessions), `FailedPrecondition` (the caller is below revision 13, the session is not the open session of a member, or the session already has an `SPIRows` call). |
| `TrunkKeys` | unary         | `KeysRequest` -> `KeysResponse`: trunk SAs for packets from the called relay to the caller (see "Trunk"). `refused_spis` has the SPIs that the called relay holds from another receiver or in a row to the caller. Errors: `Unimplemented` (the called relay serves no VPC relay sessions), `FailedPrecondition` (the caller is below revision 13, or the session is not the open session of a member), `InvalidArgument` (an SA VNI is not 0, or an SA lane is not 0). |

A member of a mesh is one relay process, and its relay name identifies it.
Many relays can have one relay ID, so the mesh does not use the ID to tell
members apart. Two members have one session. The relay with the lower name
dials, from its listening socket, and calls `Open`. The other relay refuses a
session that the relay with the higher name dialed. A new session of the two
relays replaces the session before it. The other calls of a session are valid
only after `Open` passes. A relay keeps the relay ID that each member gave in
`Open`, to check the grant of a `Visit` call (see "Relay").

A relay closes a session with a `MeshCloseCode`: `NOT_MEMBER` (the name of the
other relay is not in its member set, is not the name that it dialed, or the
certificate failed the check of the relay host), `UPGRADE` (the revision of the
other relay is below its minimum, or below 3, the first revision with `Open`;
see "Revisions") or `RESTART` (the relay stops on purpose, and its attachments
are gone).

A relay closes with `RESTART` when it stops: at the end of a drain, and not
at its start. During the drain its mesh sessions stay open, and the other
relays keep its entries, routes and SPI rows. Thus an agent of the draining
relay gets the packets of the agents of other relays until it moves (see
`Drain` in "Relay"). If its new attachment on another relay has a prefix of
the old one, the rules for one prefix (below) give the route to the new one.

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
bits, a subject that is not an agent ID of that VPC, a tag out of range, a
prefix that does not parse or more than 64 prefixes. A refused entry does not
end the call. A second `Presence` call on a session gets `FailedPrecondition`.

The relay keeps at most 65536 entries of one member, and it refuses each new
entry above that number. Before it refuses one, it drops the entries of that
member that the session of the call did not send.

The entries of a member stay after its session ends, with their routes and
with no time limit. The relay drops them at once when the member closes with
`RESTART` or leaves the member set, also when the member was down before it
left. A member whose address changes leaves the member set and comes back.
When the member has a new session, the relay keeps each entry of an older
session until the new session sends it again (the same attachment ID and
generation) or replaces it with a higher generation. At `end_of_full_set` it
drops the entries that the new session did not send. It also drops them 10 s
after the new session opened, if no `end_of_full_set` came in that time, with
or without a `Presence` call. If the new session ends first, the entries stay,
and the 10 s start again when the next session opens.

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
drops the entry for one of the reasons above. The route of an entry stays
while the relay of the entry has no session. A peer frame for the route then
drops (see "Mesh datagrams"), and the PSP packets of an SPI row and the clear
inner packets to that relay drop when it is down (see below).

A relay tells each other relay at revision 13 or later of the SPI rows that it
has for receivers on that relay (see "Trunk"). It opens one `SPIRows` call on a
mesh session, at the first such row. An `SPIRow` has the VPC, the sender tag
of the session of the sender on the calling relay, the SPI, the overlay
address of the receiver and `expires_in`, the time that the row has left. The
SPI names the row: the calling relay has each SPI in one row to the called
relay. The sender tag tells which entry is the sender, for the checks of the
packets. The calling relay sends a row when
`RegisterSPI` makes it, and again with the new `expires_in` at each later
`RegisterSPI` for it. It sends the row with `removed`, and with no address and
no `expires_in`, when the row ends on the calling relay or goes to a receiver
that is not on the called relay. The rows of one change go in one or more
messages of at most 256 rows.

`RegisterSPI` does not wait for the called relay, so the first packets of a
row can come before the row. On a new session, the calling relay sends each
row that it has for the called relay again. It does not send the rows that
ended while it had no session. If the call fails, the calling relay makes no
new call on that session, and it keeps its rows.

The called relay keeps the rows of each member by SPI. It takes the member
from the session, never from the message. A row replaces the row of that
member with the same SPI. The called relay refuses a row with a sender
tag out of range, with a reserved SPI or, without `removed`, with a VPC or an
address that does not parse or an `expires_in` that is not positive. A refused
row does not end the call. The other checks of a row are those of its packets
(see "Trunk"), so a row can come before the entry of its sender or before the
route of its destination. A row ends at `removed`, when its `expires_in`
passes, when the member opens a new session, and when the member closes with
`RESTART` or leaves the member set. The rows stay when the session ends for
another cause, as the entries do. They have no idle time.

When the other relay is down, a relay has no trunk to it, so the packets of
its rows and the clear inner packets to that relay drop at once. The rows
stay, and they carry packets again when the other relay has a session again.
A clear inner packet also needs the new trunk SA of that relay. The sender of
such a packet gets no `NoRoute` while the route of the destination stays,
unless it must visit the other relay (see below).

For an address of a route of another relay, `ResolvePeer` answers
`REACH_TRUNK` only when all of these are true:

- The session of the caller is at revision 10 or later. It gets the routes of
  other relays: it has a `Session` call, and its `Hello` has no
  `local_routes_only`. It has a sender tag, which it has from its first
  attachment.
- The newest mesh session with the other relay is open, and each of the two
  relays has the trunk SA of the other on that session.
- The other relay is at revision 13 or later. The rule is the same for a
  caller in PSP mode and in QUIC mode: the relay does not know the mode of the
  peer, and a PSP-mode caller sends to a QUIC-mode peer in trunk packets.

In each other case the call returns `NotFound`, as for an address with no
route. This is also the answer in the 3 s after the session with the other
relay ended, and on a new session before the two relays have its SAs. The peer
sessions that are open in that time keep their paths, because the SAs stay for
those 3 s (see "Trunk"). The answer has the `subject` and the attachment IDs
of the entries of the session that has the address, the lowest generation
first.

`ResolvePeer` answers `REACH_VISIT` with `home_relay` only when all of these
are true. The same rule sets `home_relay` in `NoRoute`.

- The session of the caller is at revision 12 or later, gets the routes of
  other relays and has a sender tag, as for `REACH_TRUNK`.
- The home relay of the address is a member that is down: its session ended
  3 s ago or more, and no new session opened. Thus the answer never comes
  while the trunk can carry the traffic.
- That session did not close with `RESTART`, and the member gave a relay ID in
  `Open` on it.
- No other member gave the same relay ID on its last session, and it is not
  the relay ID of this relay. An agent cannot choose one of two relays that
  have one ID.

The home relay of an address is the member whose entry has the route of the
address, because a relay keeps the entries of a member that is down. For an
address with no route, the host of the relay can tell the home relay.
`home_relay` is the `RelayRef` that the member gave in `Open`. The answer has
no `subject`, no `attachment_ids` and no `p2p`. When the member is up again,
the answer is `NotFound` until the two relays have the trunk SAs, and then
`REACH_TRUNK`. When the member stops with `RESTART` or leaves the member set,
its entries go, and the answer is `NotFound`.

When the rule is true for a sender, the relay sends it `NoRoute` with
`home_relay` for a peer frame, a data frame and a PSP packet with the relay SA
to the address, and for the PSP packet of an SPI row to the home relay, at
most one each second for each address. The relay does not open the packet of
a row: the address in `NoRoute` is the `destination` of the `RegisterSPI` call
of the row, and the home relay is the member that the row sends to. On a host
with the XDP program, the first such `NoRoute` can come up to 1 s later: the
program has the row until the relay looks at its rows again, which it does
each second. A sender below revision 12 gets no `NoRoute` for an address with
a route, as before. A sender that Permit denies gets `NoRoute` with no
`home_relay`. The agent can then attach to the home relay as a visitor (see
`Visit` in "Relay").

An agent opens a peer session to an address with the answer `REACH_TRUNK` as
to an address of its own relay, and it sends all its packets to its own relay.
The packets of the peer session go in peer frames, and between the relays in
mesh datagrams (see "Mesh datagrams"). The agents learn the mode of each other
in `Open`, so an entry has no mode. Two PSP-mode agents make SAs for each
other, and each one calls `RegisterSPI` on its own relay: their PSP packets go
between the relays with no change, and no relay opens them. When one of the
agents is in QUIC mode, each agent sends through its relay, in data frames or
with its relay SA, and the inner packets go between the relays in trunk
packets (see "Trunk"). The grant of the peer is from the other relay, so the roots that an
agent checks grants with must cover the certs of all relays of the mesh.

A peer session belongs to the relay session that it started on. When an agent
moves its attachment to another relay, on a spare or after `Drain`, it closes
the peer sessions of the old relay session. Its next packet to the peer opens
a new one with the answer of the new relay: `REACH_LOCAL` if the peer is on
that relay, and `REACH_TRUNK` if it is on another relay of the mesh.

An agent below revision 10, or with `local_routes_only`, opens no peer session
to such an address. It accepts the peer session that an agent of another relay
opens, and then the two agents send to each other.

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
| 7 | The mesh datagram with a type byte, and its type `0x01`: a peer frame with the sender tag. | No duty. | No duty. | Sends a peer frame for an address with a route of another relay to that relay in a mesh datagram, when that relay is at revision 7 or later, and sends no `NoRoute` for it. Sends no mesh datagram to a relay below revision 7. Checks each mesh datagram of another relay, and gives its frame only to a session of its own. Drops a mesh datagram with another type. |
| 8 | `Mesh.SPIRows` on the called relay. The trunk packet with a sender tag: a whole PSP packet of an agent. | No duty. | No duty. | Keeps the SPI rows that another relay gives in `SPIRows`. Opens a trunk packet with a sender tag, checks it with the rows and the entries of the other relay, and sends its PSP packet only to a session of its own. With a relay at revision 8 or later: opens one `SPIRows` call for its rows to that relay, and sends the PSP packets of those rows in trunk packets. Makes no `SPIRows` call to a relay below revision 8, sends it no trunk packet with a sender tag, refuses its `SPIRows` call with `FailedPrecondition`, and keeps that session. |
| 9 | The trunk packet with a sender tag on lane 1: a clear inner packet of an agent. | No duty. | No duty. | Opens a trunk packet with a sender tag and a lane 1 SA, checks it with the replay window and the entries of the other relay, and sends its inner packet only to a session of its own: in a data frame, or sealed with the SA of a PSP-mode agent. With a relay at revision 9 or later: sends the inner packet of a data frame, or of a PSP packet that it opens, for an address with a route of that relay in a lane 1 trunk packet, and sends no `NoRoute` for it. Sends no such trunk packet to a relay below revision 9: it drops the inner packet, and sends no `NoRoute` for it. |
| 10 | The answer `REACH_TRUNK` of `ResolvePeer`. | Opens a peer session to an address with the answer `REACH_TRUNK`, as to an address of its own relay. | No duty: it sends `local_routes_only`, so it gets `NotFound`. | Answers `ResolvePeer` for an address with a route of another relay with `REACH_TRUNK`, `subject` and `attachment_ids`, when the session of the caller is at revision 10 or later, gets the routes of other relays and has an attachment, the other relay is at revision 9 or later, and each relay has the trunk SAs of the other on the open mesh session. Answers `NotFound` in each other case, as a relay at revision 6 does. With a mesh, refuses an `Attach` with more than 64 prefixes. |
| 11 | `Relay.Visit`. | No duty: an agent of this revision makes no `Visit` call. | No duty. | With a mesh: accepts `Visit` after the checks of the grant, the caller and the address, sends the traffic of its own sessions for the visit prefix to the visitor session, and sends nothing of a visitor to another relay. With no mesh: answers `Unimplemented`. |
| 12 | The answer `REACH_VISIT` of `ResolvePeer`, and `home_relay` in `NoRoute`. | On `REACH_VISIT`, and on a `NoRoute` with `home_relay`, keeps its peer sessions, with the path of the session to the address down: a new peer session of the same agent replaces it. The agent with the lower address opens a visitor session to `home_relay` with `local_routes_only`, calls `Visit`, and opens the peer session there. The agent with the higher address waits 2 s for that peer session, and then visits in the same way if none came. An agent with a peer session to the address on its attached session, with the path up, does not visit. When the two agents visit, the peer session on the relay of the higher address stays. Data goes on a visit only when the attached session and the visitor session are in PSP mode and the path probe at the device MTU passes. The agent asks its own relay again at an interval and moves the peer back when the answer is `REACH_LOCAL` or `REACH_TRUNK`. | No duty: it sends `local_routes_only`, so it gets neither. | Answers `ResolvePeer` with `REACH_VISIT` and `home_relay`, and sends `NoRoute` with `home_relay`, when the session is at revision 12 or later, gets the routes of other relays and has an attachment, and the home relay of the address is a member that is down for 3 s or more, did not close with `RESTART`, and gave a relay ID that no other relay of the mesh has. Answers as a relay at revision 11 in each other case. |
| 13 | The PSP packet of an agent between two relays, with no change and with no trunk SA. One SA lane for a trunk. The trunk formats of the revisions 5, 8 and 9 end here, and the duties of a relay in those lines apply only between relays at revision 13 or later. | When `RegisterSPI` returns `AlreadyExists` for rows that it has, closes the peer session, so that the next peer session has new SAs. | No duty. | Has a trunk only with a relay at revision 13 or later: makes no `TrunkKeys` call and no `SPIRows` call to an older relay, refuses those calls of it with `FailedPrecondition`, sends it no packet of a sender, answers no `REACH_TRUNK` for it, and keeps that session. Sends the PSP packet of a row to another relay with no change, and seals only clear inner packets and its own messages with the trunk SA. For a packet from the address of a member: opens it when a trunk SA for that member has its SPI, sends it with no change to a session of its own when a row of that member has its SPI, and drops it in each other case. Keeps each SPI in one use for the packets to a member: refuses `RegisterSPI` with `AlreadyExists`, ends a row that goes to a member with its SPI in use, and returns a trunk SA with the SPI of a row in `refused_spis`. |

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
