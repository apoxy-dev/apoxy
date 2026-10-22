# VPC datapath control: wire format

The control plane of VPC Tunnels v2. The `.proto` files here define the
messages and services. The runtime is `pkg/vpc/rpc`, and
`protoc-gen-go-vpcrpc` makes the Go stubs. Regenerate with
`go generate ./proto/vpc/datapath/v1`.

## Connections

QUIC v1, TLS 1.3 with mTLS, on the QUIC socket of a relay (UDP 443). The ALPN selects the channel and the
service that each side serves:

| ALPN           | Between                  | Service | Served by |
|----------------|--------------------------|---------|-----------|
| `apoxy-vpc/2`  | agent or VTEP and relay  | `Relay` | relay     |
| `apoxy-mesh/1` | relay and relay          | `Mesh`  | both      |

A relay has a second UDP socket, the PSP socket (UDP 1000). It carries the
PSP packets of agents (first byte `0x04` or `0x29`), which the relay opens
(see "QUIC and PSP bridge"), the path probes and the lane keep-alives of
agents, and the trunk packets of the other relays of the mesh (see "Trunk").
The QUIC socket drops each packet that is not QUIC.

`Welcome.psp_host` and `Welcome.psp_port` tell an agent where the PSP socket
is. `psp_host` is an IP address, and when it is empty, the PSP socket is at the
host that the agent dialed for the session. A relay always sends it empty,
because it cannot see the host that an agent dialed. `psp_port` is the local
port of the PSP socket. An agent ends the dial with an error on a `psp_host`
that is not an IP address and on a `psp_port` of 0. `MeshOpenRequest` and
`MeshOpenResponse` have the same two fields for the PSP sockets of two relays:
the dialer sends to the host that it dialed, and the listener sends to the
remote IP address of the mesh session, each at the port that the other relay
gave. A relay refuses a mesh session with a relay that gives port 0, because
each relay at revision 22 or later has a PSP socket.
An agent has one UDP socket for the two relay ports.

### Relay datagrams

QUIC DATAGRAM frames on a relay session carry data in QUIC mode. The relay
drops each other frame type.

```
data:            type (1 B) | VNI word (4 B) | inner IPv4 or IPv6 packet
type:            0x03 data frame
```

The VNI word is the first word of the PSP VC: the VNI (24 bits), then 8 flag
bits. The relay ignores the flags. It takes data frames from a session in
each mode. It drops a data frame if the VNI is not the network ID of the
session, if the session does not route the inner source, or if no session
routes the inner destination (then it sends `NoRoute`). It sends the frame to a
QUIC-mode agent with no change, on the main or extra connection of its flow.
When a session of another relay of the mesh routes the inner destination, the
relay sends the inner packet to that relay (see "Trunk").

### Data mode

Each session starts in QUIC mode. It changes from QUIC mode to PSP mode, on
the open session, when the agent calls `Rekey`, and back to QUIC mode when its
PSP path is lost (see "PSP path check"). `Hello.mode` tells
the relay which mode the agent wants, and the relay only counts it. After
`Welcome`, an agent that wants PSP mode sends path probes to
the PSP socket of the relay, while its `Attach` call runs. These probes have the
size of the largest inner packet of QUIC mode: the device MTU of the agent,
and 1308 B at most. When the first probe passes, the agent calls `Rekey` with
its SAs for the relay. When no reply comes in 1 s, the session stays in QUIC
mode and the agent probes again with backoff (30 s, doubling to 10 min). After
a probe that failed, two probes in a row must pass, 5 s apart. In PSP mode the
agent sends no such probe: the PSP path check sends its packets. An agent with
QUIC mode in its config sends `fallback_reason` `CONFIG` and does not probe.

A probe has a counter, which the agent increases for each probe that it sends
with the keys of one relay connection. The relay answers a probe on its PSP
socket when the source IP address of the probe is the IP address of the QUIC
connection of its session. The PSP address of a session is the source address
of such a probe with a larger counter than each one before it. The relay
takes the PSP packets of the session from this address and from its lane
ports, and it sends the PSP packets for the agent to this address. A probe
with an old counter gets an answer, but it does not change the PSP address.
A session with no PSP address has no PSP packets in the two directions.

On a `Rekey` from a session in QUIC mode, the relay makes its relay SAs for
the session, applies the SAs of the agent, sets the mode to PSP, and sends its
rekey on the `Session` stream. From then on it seals the packets for the agent
with the SAs of the agent. The agent sends PSP packets when it has the relay
SAs. The session, its attachments and their addresses stay. If a step fails,
or if the relay refuses each SPI of the agent, the mode stays QUIC and the
session has no relay SAs.

### PSP path check

In PSP mode, a BFD session (RFC 5880, with the states Down, Init and Up, no
authentication section and no echo) checks the PSP path of the relay session.
Each side sends one BFD control packet each 2 s, and one more at each change
of its own state. The packet has the state of its sender, so each side knows
if the other side hears it.

The BFD packet is the payload of a path probe: its 24 B come after the probe
header, and the probe has the flag `0x02` in its flags byte. The tag of the
probe covers it. The agent sends its packets to the PSP socket of the relay,
each with the next probe counter, so they keep the NAT mapping of the PSP path
and give the relay the PSP address of the session, as each probe does. The
relay sends no reply to a probe with a BFD packet. It sends its own BFD
packets to the PSP address of the session, as probe replies with the source
address of the agent.

A side calls the PSP path lost when the other side says that it is Down after
the two sides were Up, or when no BFD packet comes for 6 s (3 packets). That
side then changes the session to QUIC mode, with no call and no message. It
first sends one BFD packet in the Down state, so the other side makes the
change at once when that packet passes, and after its own 6 s when it does
not. The session, its attachments and their addresses stay.

- The agent sends its data as data frames, opens the extra connections
  again, and stops its lane ports and the rekeys of its SAs for the relay. Its fallback reason is `PROBE_TIMEOUT`. It then
  probes with backoff, as a session whose first probe failed, and calls
  `Rekey` when two probes in a row pass.
- The relay sends the data for the agent as data frames, and deletes its relay
  SAs and the SAs of the agent, so it sends no more rekeys for the session. It
  takes a later `Rekey` as on each session in QUIC mode.

An open TCP connection continues after the change: TCP sends the packets that
the PSP path lost again. A packet above the data frame limit (1308 B inner)
does not fit QUIC mode.

### Relay connections of an agent

An agent keeps one to three relay connections, each on another relay, and it
attaches on each one. Each attachment has its own address, from the relay of
its connection. `AttachRequest.rank` is 0 for the first connection, and a
later one gets the next number, so the relays select one announcer for a
prefix that the agent advertises on each connection (see "One prefix, many
announcers"). The agent sends a packet on the connection of the source
address of the packet. A packet with another source, from an advertised
prefix, goes on the connection with the lowest rank that does not drain.
When a connection ends, the agent removes its address and dials another
relay. The other connections carry data in that time.

### QUIC and PSP bridge

The relay connects QUIC-mode and PSP-mode agents. It opens and seals each
packet that an agent sends to it.

- Relay SAs: the relay sends a rekey (`KeysRequest` with `OfferSAs`) after
  the change to PSP mode, and a new one before the SAs expire. The agent
  seals with them each packet that it sends to the relay. The relay checks the
  replay window, the source address and port of the packet, the VNI and the
  inner source. It sends the inner packet as a data frame to a QUIC-mode
  agent, with the VNI word of the PSP packet, and seals it with the agent SAs
  of a PSP-mode agent.
- Agent SAs: a PSP-mode agent gives the relay its own SAs with `Rekey`. The
  relay seals with them the data frames from QUIC-mode agents, and the inner
  packets that PSP-mode agents sealed with a relay SA.

The meters of the connection apply to the packets of a relay SA.

When the two agents are on two relays of a mesh, the relay of the sender opens
the data frame or the PSP packet, and the relay of the receiver sends the
inner packet to the receiver. The inner packet goes between them in a trunk
packet (see "Trunk").

### Circuit breaker

A sender of data has a breaker (RFC 8084) for each PSP receiver, and one for
its QUIC data frames. A receiver reports the counters of its SAs in `RxReport`:
the packets that it accepted and the highest sequence number. A relay sends
them for its relay SAs on `Session` each second, only when they change. The loss of an
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

Two relays of a mesh send each other only trunk packets, to the PSP socket of
each other. A relay opens each packet that its own agents send to it (see
"QUIC and PSP bridge"), so no PSP packet of an agent goes to another relay. A
clear inner packet for an agent of another relay, and a message of the relay
itself, go in a trunk packet, which the relay seals with a trunk SA. Thus each
packet between two relays has the 40 B of PSP one time. There is no NAT
between two relays.

A trunk SA is a PSP SA with VNI 0 on lane 0, and the VNI field of its packets
carries a tag. A trunk has one SA lane, and its SAs have a replay window.

```
trunk packet:    PSP header and VC, with the tag (24 bits) in the VNI field | payload
tag 0:           a message of the relay itself
tag 1 and up:    the sender tag of the session of the sender, with a clear inner packet
message:         type (1 B) | run ID (8 B) | zero padding
type:            0x01 full-size probe, 0x02 answer
```

A trunk packet with a message has the next header value 63. A trunk packet
with a clear inner packet has the next header value of that packet: 4 for
IPv4 and 41 for IPv6.

Each relay makes the SAs for the trunk packets that it receives, and gives
them to the other relay with `TrunkKeys` on the open mesh session. On each new
session, a relay offers a new trunk SA (`OfferSAs`). It sends a new SA before
the SA expires (`RekeySA`), as for the relay SAs of an agent. The called relay
returns in `refused_spis` the SPIs that it does not take, and the caller
offers SAs with new SPIs, at most 4 times for one change. After a call that
failed, the caller waits as before a dial (200 ms, doubling to 10 s, each with
up to 50% more) and offers a new SA. `Unimplemented` tells that the called
relay has no trunk, and the caller makes no more calls on that session. When
the session ends, or a new session replaces it, the relay deletes the trunk
SAs of the two directions of that session at once.

When each relay gave its SA on a session, each relay sends a full-size probe:
a message of 1412 B, so that the UDP payload is 1452 B, the largest that a
relay reads. The other relay answers with a message of the same size and run
ID. It answers at most 10 probes each second. A probe run sends up to 3
packets 300 ms apart. If no answer comes in 1 s, the relay has the trunk as
limited to an inner MTU of 1280, and it starts a new run each 30 s until one
passes. After a run that passes, the trunk carries an inner MTU of 1412. The
relay makes the routes of the other relay only after the first result of a
session (see "Mesh").

The largest MTU of a VPC network is also 1412. A relay gives an agent at most
1412 as the MTU of the network, also for a network object with a larger number
from before a check of its spec. The sizes on a path that carries 1500 B, with
an IPv6 header of 40 B and a UDP header of 8 B:

| Trunk packet | PSP overhead | Largest inner packet | UDP payload |
|--------------|--------------|----------------------|-------------|
| After a full-size probe that passed | 40 B | 1412 B | 1452 B |
| With no full-size probe that passed | 40 B | 1280 B | 1320 B |

A relay sends a clear inner packet to another relay when the active announcer
of the destination is an attachment of that relay. It holds the inner packet
of a data frame of a QUIC-mode session, and of a PSP packet that an agent
sealed with a relay SA. The checks of the data frame or of the relay SA come
first. The relay seals the inner packet with the trunk SA of the session of
that relay, with the sender tag of the session of the sender in the VNI field.
It sends the trunk packet from its PSP socket to the PSP socket that the other
relay gave in `Open`. It sends no `NoRoute` for such a packet, because the
address has a route. It drops the inner packet, and counts the drop in
`apoxy_vpc_relay_dropped_packets_total`, in these cases:

- The relay has no trunk SA of the other relay on the session (`no_keys`).
- The inner packet is above the inner MTU of the trunk (`mtu`). The relay
  does not send the packet in parts, and the agent gets no message for this
  drop.

The relay that gets a trunk packet drops it at the first of these checks that
fails:

1. The packet has the form of a PSP packet (`malformed`).
2. A trunk SA that this relay gave has its SPI (`unknown_spi`), and the ICV
   and the replay window of the SA pass (`open`).
3. The SA is of the open mesh session with the other relay (`old_session`).
4. The packet comes from the PSP socket that the other relay gave in `Open`:
   the same IP address and port (`unknown_source`).
5. A trunk packet with tag 0 goes to the relay itself: a probe gets its
   answer, and an answer ends the probe run with the same ID.
6. A record of the other relay on that session has the tag (`no_context`).
   The packets of one tag go to the VPC of its first record. A record with
   the tag of another VPC gets a warning and no packets.
7. A record of the tag has the inner source address (`source`).
8. An attachment of this relay announces the inner destination in that VPC
   (`no_route`). The relay takes its first announcer in the order of "Relay",
   also when the active announcer is on another relay.
9. The target is not a trunk (`trunk_to_trunk`), so an inner packet goes over
   one trunk at most.

Then it sends the inner packet as it sends the inner packet of a data frame
of one of its own sessions: in a data frame to a QUIC-mode agent, on the main
or extra connection of its flow, or sealed with the SA that a PSP-mode agent
gave with `Rekey` (`no_keys` when it has none). The data frame has the network
ID of the VPC and zero flags, because a trunk packet has no VNI word. The
relay of the receiver does not know the mode of the sender.

A relay also counts the packets of agents between it and each mesh member.
These metrics have one set of series for each member that the mesh has now,
and none for each agent. Their labels are `peer_relay`, the relay name of the
member, `peer_relay_id`, the last relay ID that the member gave (empty if it
gave none), and `direction`: `tx` to the member, `rx` from it.

- `apoxy_vpc_relay_trunk_packets_total` and `apoxy_vpc_relay_trunk_bytes_total`:
  the trunk packets with a sender tag, and their UDP payload bytes. The `tx`
  counts have the packets that the relay sealed for the member. The `rx`
  counts have the packets of the member that passed check 6. The probes and
  their answers do not count.
- `apoxy_vpc_relay_trunk_dropped_packets_total`, also with the label `reason`:
  `tx` has the packets to the member that the relay dropped after it found the
  `ports` entry of the trunk port (`mtu`, `no_keys`, `trunk_to_trunk`,
  `local_only`). `rx` has the packets of the member that the relay dropped
  before it found the `ports` entry of the out port (`malformed`,
  `old_session`, `unknown_source`, `no_context`, `source`, `no_route`,
  `no_target`, `punt_full`). Each of these series is there from the start.
- `apoxy_vpc_relay_mesh_rtt_seconds`: the smoothed RTT of the QUIC connection
  of the mesh session. A member with no session has no value.

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
  messages until FIN and gets one message. A server-stream call sends one
  message and gets messages until the status. A bidirectional call sends and
  gets messages at the same time: the caller until its FIN, and the called
  side until the status.
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
| `Session`       | bidi  | Agent: `Hello{mode, fallback_reason, version, name, local_routes_only, instance}`, then `Ack{rev}`, `Status` (ICV failures; the first one after `Config` also has the time to connect) and `RemoteAddresses{attachment_id, attachments}`. Relay: `Welcome` (reflexive address, lane port limit, version, PSP address, relay ID), `Config`, then `RouteDelta{rev}`, `NoRoute`, rekey (`KeysRequest`), `Config`, `Drain`, and in PSP mode `RxReport` (only the last one waits). |
| `Attach`        | unary | `AttachRequest{vpc, name, labels, routes, rank}` -> `AttachResponse{attachment_id, routes, addresses}`. `routes` has one status for each advertised route. `addresses` has the address prefixes that the relay gives the attachment. Errors: `FailedPrecondition` (the session sent no `Hello`), `AlreadyExists` (another session of this relay has the address). |
| `Rekey`         | unary | `KeysRequest{op, generation}` -> `KeysResponse`: SAs for traffic from the relay to the agent. The first one from a session in QUIC mode changes it to PSP mode (see "Data mode"). Errors: `FailedPrecondition` (no `Session` call), `InvalidArgument` (an SA VNI is not the network ID), `Unavailable` (the relay has no PSP bridge, or it cannot make its relay SAs). |
| `RegisterLanes` | unary | `{ports, receive}` -> `Empty`: replaces the lane ports of the session. The relay ignores `receive`. Errors: `InvalidArgument` (more ports than `Welcome.max_lanes`, port 0, the session port, a repeated port), `FailedPrecondition` (no PSP address). |

`Welcome.relay_id` is the ID of the relay. `Route.relay` is the `RelayRef` of
the relay that has the origin of the route, also of this relay for a local
origin. It can have the ID and no addresses. `RemoteAddresses` gives, for one
attachment of the session, the attachments of the same name on the other
relays of the agent: the relay ID that each `Welcome` gave, the attachment ID
and the address prefixes there. Each `RemoteAddresses` replaces the last one
for its attachment. `KeysRequest.generation` is the key attempt of the agent,
from 1. The relay copies it from the `Rekey` request that changes the mode
into its `OfferSAs`, and its own renewals carry 0.

A relay with a mesh refuses an `Attach` with more than 64 prefixes, the
addresses and the advertised routes together, or whose entry does not fit in
one `PresenceUpdate` (`InvalidArgument`), because the other relays refuse
such an entry (see "Mesh"). A relay with no mesh has no such limit.

Many agents can have one SPIFFE ID. `Hello.name` is the name of the base
attachment of the agent, and `Hello.instance` is a random number that the
agent process makes when it starts. One agent process is one SPIFFE ID, one
name and one instance. An agent below revision 16 sends no instance, which
reads as 0. The relay keeps these fields with each attachment, so it refuses
an `Attach` on a session that sent no `Hello` (`FailedPrecondition`).

Each prefix has a set of announcers: each attachment that lists the prefix as
an address or as an advertised route, on this relay or on another relay (see
"Mesh"). Each connection of an agent to a relay is its own announcer. An
`Attach` does not fail because another agent announces the same advertised
route. An address that the relay assigns has one attachment on a relay: an
`Attach` gets `AlreadyExists` when another session of the same relay has the
address.

The relay checks each advertised route of an `Attach`, and refuses a route
that is:

- a default route, IPv4 or IPv6 (`ROUTE_RESULT_DEFAULT_ROUTE`);
- an IPv4 prefix or an IPv4-mapped IPv6 prefix (`ROUTE_RESULT_IPV4`): an
  IPv4 address is reachable only in the /96 of an attachment;
- a prefix that overlaps the network of the VPC, which is the /72 with the
  addresses of the attachment (`ROUTE_RESULT_OVERLAPS_VPC`).

A refused route does not fail the `Attach`: the attachment gets its addresses
and its other routes. The attachment is not an announcer of a refused route,
so no session gets the route, and the entry for the other relays does not have
it. A route that does not parse is not a route, and fails the `Attach` with
`InvalidArgument`.
`AttachResponse.routes` has one status for each advertised route, in the order
of the request, with the prefix in the masked form. An agent below revision 16
gets no statuses. An agent reads each result that is not
`ROUTE_RESULT_ACCEPTED`, also one that it does not know, as a refused route.

One announcer of a prefix is active, and it gets the packets for the prefix.
The others are standby. Each relay selects with the same rules, and the rules
use only the set, not the order in which the announcers came. Thus all relays
with the same set select the same announcer. The order is:

1. The state: `NORMAL`, then `DRAINING`, then `SUSPECT`, then a state of a
   later revision.
2. For `NORMAL` announcers: one whose `active_from` time has passed, then one
   that is still in its hold time (see below). When each `NORMAL` announcer is
   in its hold time: the earlier `active_from`.
3. The agent process with the lowest SHA-256 hash of these bytes: the SPIFFE
   ID, a zero byte, the name, a zero byte, the instance as 8 bytes (big
   endian), and the prefix as text. Each prefix has its own order of agents.
4. For the connections of one agent process: the lower `AttachRequest.rank`,
   then the lower relay name, then the lower attachment ID. The agent gives
   the rank, and the default is 0.

When one agent process has two attachments with the prefix on one relay, only
the one with the later attach is in the order (then the one with the lower
attachment ID). This is the case after a reconnect to that relay. The relay
compares the generation at the attach, not the generation of a later state
change. The older attachment stays in the set, and it comes in the order
again when the newer one ends.

The relay of an attachment gives it its state, and all attachments of one
session have the same state:

- `SUSPECT`: the relay does not hear the agent. The relay sends a QUIC
  keep-alive on each agent connection after 2 s with no packet, and each QUIC
  stack answers it, so this works for each agent revision. The relay checks
  each 250 ms. After 6 s with no QUIC packet from the agent, the session is
  `SUSPECT`. It is `NORMAL` again when a packet comes 4 s or more after the
  first packet of a run of packets with no silence above 3 s. The session, its
  addresses and its routes stay until the idle timeout of the connection ends
  them. QUIC uses the lower idle timeout of the two sides: 15 s on the relay and
  6 s on the agent. An agent sends its own keep-alive each 2 s, so a lost NAT
  entry opens again before the 6 s.
- `DRAINING`: the relay drains. It gives the state to all its attachments at
  the start of the drain, before it sends `Drain`. A session that is `SUSPECT`
  stays `SUSPECT`.

A state change does not remove the attachment from the set. The relay changes
the state of the announcer and selects again. The route entries of a
prefix move only if its active announcer changes, so the only announcer of a
prefix stays active in each state.

An announcer that comes, or that returns to `NORMAL`, does not replace a live
active announcer at once. Its relay sets `active_from` to the time of the
attach, or of the last return to `NORMAL`, plus 30 s. Until that time, each
`NORMAL` announcer whose `active_from` has passed comes before it. When each
`NORMAL` announcer of a prefix is in its hold time, the one with the earliest
`active_from` comes first, so a prefix with one announcer and a new set have
an active announcer at once. That announcer stays active when its hold time
ends. When the last hold time of the set ends, the order is again that of the
hash, the rank, the relay and the attachment ID, which can move the active
role one time. An announcer in its hold time comes before each `DRAINING` and
each `SUSPECT` one, so it does not wait when the active announcer is not
`NORMAL` or is gone. A reconnect of the active announcer is a new attachment
with a new hold time: a standby announcer whose hold time has passed is active
until that hold time ends. Each relay selects again when a hold time ends.
Each relay reads its own clock, so two relays can select different announcers
only for the time by which their clocks differ.

`RouteDelta` gives the active announcer of a prefix as the origin of its
route. A session at revision 16 or later also gets `Route.standby`: the
attachment IDs of the standby announcers that it can reach, in the order in
which they become active. When the active announcer changes, the relay
removes the route with the old origin and adds the route with the new one.
When only the standby list changes, a session at revision 16 or later gets
the route again as an add. A state change, or the end of a hold time, that
changes neither the active announcer nor the standby list sends nothing.

- A session gets no route for a prefix that its own agent process announces.
  It gets the routes of the other agents of its SPIFFE ID.

The /96 address prefixes of the attachments in the network of the VPC (its
/72) get no route each. Each /88 slot that has such a /96 gets one Route: the
prefix is the /88, the origin is the ID of the relay that holds the slot, and
`Route.relay` is the `RelayRef` of that relay. The holder is an attachment of
this relay first, then the lower relay ID, then the lower attachment ID. Each
session gets the Route of a slot of this relay. Only a session that gets the
routes of other relays gets the Route of a slot of another relay.

The first route table of a session comes in `RouteDelta` parts of at most 256
routes and 1 MiB, each with its own `rev`. All changes of one prefix are in one
part. After the parts, one `RouteDelta` with no routes ends the first table.

Each announcer of a prefix can send from it, also a standby one, because
traffic from the network behind it can leave through each of its connections.
A session that is no announcer of a prefix cannot send from it.

A connection has one `Session` call and lives as long as that call. A relay
closes a connection with a `RelayCloseCode`: `CERT` (the agent cert failed a
check; get a new cert before the next dial), `DRAIN` (move to another relay)
or `UPGRADE` (the agent revision is below the minimum of the relay; see
"Revisions").

`Drain` tells an agent that the relay stops soon. From then on the relay
refuses each new connection with `DRAIN`, and it closes the sessions that are
left when the drain ends. Before it sends `Drain`, the relay gives all its
attachments the state `DRAINING` (see "One prefix, many announcers"), so each
relay selects a standby announcer of another relay for their prefixes. `alternates` lists the relays that the agent can
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

An agent that gets `Drain` on a session keeps the session, with its
attachment and its address, until the relay closes it. The address is not
preferred from then on: a new connection of the host uses the address of
another session, and the open connections continue. The agent opens one new
connection in place of the draining one. It dials each address of each
alternate in the order of the list, then the other relays that it knows, it
skips a relay on which it has a session, and it attaches on the first relay
that takes it, with the next rank. With no such relay, it dials the relays
that it knows after the relay closes the session.

In QUIC mode an agent can add up to 3 extra connections from the same socket
that carry data datagrams. Each one sends
`Hello{shard: {attachment_id, index}, version}` as its first `Session`
message, gets `Welcome`, and makes no other call. The relay refuses the join
if the index is not from 1 to 3 (`InvalidArgument`), if no open session has
the attachment (`NotFound`), if that session has another agent identity
(`PermissionDenied`), or if the connection already has a `Session` call
(`FailedPrecondition`). A new extra connection with the same index replaces
the old one. An extra connection closes when its main session closes.

The relay accepts an agent cert only if it chains to the agent CA, its SAN is
an agent ID, and the agent is not revoked in its VPC. It checks in the TLS
handshake and again for open sessions when the trust data changes. A session
does not end at the NotAfter of its cert: the cert must be valid at the
handshake, and the later checks of an open session use the time of its
handshake. Each call must name the VPC in the cert.

An agent sends each SA lane from its own UDP port, so that the lanes use more
NIC queues. The relay forwards PSP packets from the lane ports of a session as
from the session. A lane port is at the IP address of the session; the relay
does not check that another session uses it. The lane ports go away when the
session closes or moves to a new address. An
agent registers lane ports only when `Welcome.max_lanes` is not 0 and the
reflexive port is its local port. `Welcome.max_lanes` is the limit of the
relay in each data mode, because a session in QUIC mode can change to PSP mode.

With `receive`, the relay sends the PSP packets that it seals with the agent SA
of lane i to lane port i of the agent, after the first keepalive from that lane
port. Lane 0, a lane with no lane port, a lane port with no keepalive yet, and
all lanes without `receive` go to the session address. The relay sends from its
own port. The agent sends the one byte 0x03 from each lane port to the relay
after `RegisterLanes`, then every 5 s, so that its NAT keeps the ports open.
New lane ports, and a new session address, need a new keepalive.

### Mesh (`apoxy-mesh/1`)

| Method      | Kind          | Messages |
|-------------|---------------|----------|
| `Open`      | unary         | Dialer and listener each send `{version, name, relay, psp_host, psp_port}`. First call on a session; only the relay that dialed calls it. Errors: `PermissionDenied` (the certificate failed the check), `FailedPrecondition` (the caller has the higher name, is below the minimum revision or is not a member, or the session is already open), `InvalidArgument` (a `psp_host` that is not an IP address, or a `psp_port` of 0 or above 65535), `Unavailable` (the relay stops). |
| `Presence`  | bidi          | Caller: `PresenceUpdate{seq, vpcs, end_of_vpcs, parts}`, the attachments of one tenant of the caller. Called relay: `PresenceControl{ack}`. One call for each tenant and direction on a session. Errors: `InvalidArgument` (a message that breaks a rule below), `PermissionDenied` (a VPC of another tenant), `Unavailable` (the session ended). |
| `TrunkKeys` | unary         | `KeysRequest` -> `KeysResponse`: trunk SAs for packets from the called relay to the caller (see "Trunk"). `refused_spis` has the SPIs that the called relay does not take. Errors: `FailedPrecondition` (the session is not the open session of a member), `InvalidArgument` (an SA VNI is not 0, or an SA lane is not 0). |
| `Snapshot`  | server stream | `SnapshotRequest` -> `SnapshotPart`: the snapshot of the host of the called relay, in parts of at most 1 MiB. The first part has `total_size`. Errors: `NotFound` (the host of the called relay gives no snapshot), `ResourceExhausted` (the snapshot is above 64 MiB), `FailedPrecondition` (the session is not the open session of a member). |

A member of a mesh is one relay process, and its relay name identifies it.
Many relays can have one relay ID, so the mesh does not use the ID to tell
members apart. Two members have one session. The relay with the lower name
dials, from its listening socket, and calls `Open`. The other relay refuses a
session that the relay with the higher name dialed. A new session of the two
relays replaces the session before it: the relay first ends the old session,
its `Presence` calls and its trunk SAs. The other calls of a session wait for
the end of `Open`. A relay keeps the `RelayRef` that each member gave in
`Open`: `Route.relay` of the routes of the member and the alternates of
`Drain` have it.

A relay closes a session with a `MeshCloseCode`: `NOT_MEMBER` (the name of the
other relay is not in its member set, is not the name that it dialed, or the
certificate failed the check of the relay host), `UPGRADE` (the revision of the
other relay is below 22 or below its minimum; see "Revisions"), `RESTART` (the
relay stops on purpose, and its attachments are gone) or no code
(`UNSPECIFIED`: a normal close, or a new session replaced this one).

A relay closes with `RESTART` when it stops: at the end of a drain, and not
at its start. During the drain its mesh sessions stay open, and the other
relays keep its records, in the state `DRAINING`, with their routes. Thus an
agent of the draining relay gets the packets of the agents of other relays on
its address of that relay until the drain ends (see `Drain` in "Relay"). If
its attachment on another relay has a prefix of that one, the rules for one
prefix give the route to the other one.

Both relays send a QUIC keep-alive each second and use an idle timeout of 5 s,
so a relay sees a lost path 5 s to 6 s after the last packet of the other
relay. The dial and `Open` have 5 s together. After a session ends, the relay
that dials waits 200 ms and dials again. The wait doubles after each failed
dial, up to 10 s, and each wait gets up to 50% more at random. When the
session ends, for each cause, the relay deletes the records of the other relay
and the trunk SAs of the session at once, and has the other relay as down.

The host of a relay can keep a snapshot: the data that it needs to accept
agents while its own sources are down. The relays carry it as bytes and do not
read it. The host of a relay with no snapshot can ask the mesh for one. The
relay then calls `Snapshot` on each member with an open session, in name
order, and takes the first snapshot. It does not wait for a session to open,
and it calls no member by itself. Each member has 10 s for the whole call: the
caller sends that limit in the call header, so the call ends on the two
relays. A member with no open session gets no call and costs no time. When a
member answers with an error, the relay asks the next member, and it keeps
the session.

The called relay serves `Snapshot` only on the open session of a member, after
`Open` passed, and never on a relay session of an agent. It asks its host for
the bytes one time for each call. It sends them in order in parts of at most
1 MiB, because one message of a call holds 4 MiB, and the first part has the
size of the whole snapshot in `total_size`. A snapshot has at most 64 MiB: the
called relay answers `ResourceExhausted` and sends no part for a longer one.
The calling relay ends the call, and has no snapshot from that member, when the
`total_size` of the first part is 0 or above 64 MiB, when the parts have more
bytes than `total_size`, and when the stream ends with fewer.

The call has no signature of its own: the calling relay trusts the bytes as
much as it trusts a member of the mesh. So a member that an attacker controls
can give a relay with no snapshot a false one.

A relay tells each other relay of its attachments, one tenant (project) at a
time. On each mesh session, it opens one `Presence` call for each tenant with
attachments, and a new call when a tenant gets its first attachment. The call
is bidirectional: the caller sends `PresenceUpdate` messages, and the called
relay sends only `PresenceControl{ack}`, so an ack never waits behind data.
The caller sends:

1. The list of the VPCs of the tenant that have attachments, in `vpcs` of one
   or more messages with no part, with `end_of_vpcs` in the last one.
2. Parts. A message has at most one `PresencePart` of each VPC, and the VPCs
   with data take turns. The first parts of a VPC have its full set: an entry
   for each attachment of the caller in the VPC, with `end_of_full_set` in
   the last part of the set.
3. Then each change of a VPC: an entry for a new attachment, an entry for each
   change of its state, and an entry with `gone` for an attachment that ended.
   A VPC that gets its first attachment during the call gets its full set.

`seq` is 1 in the first message of a call, and each message adds 1. `ack` is
the highest `seq` that the called relay took in. The limits:

| Limit | Value |
|-------|-------|
| One message | At most 256 entries, 4096 parts or VPCs, and 1 MiB. |
| One VPC in one message | One part of at most 64 entries, so each VPC gets a turn. |
| Flow control | For each call: at most 1 MiB that has no ack, 2 messages in the writer of the caller, and 8 messages that the called relay did not take in. |
| Stall | A message with no ack for 5 s ends that call only. The session and the calls of the other tenants go on. |
| One entry | With a mesh, `Attach` refuses an attachment with more than 64 prefixes, or whose entry does not fit in one message. |

When a call ends with a stall while the session stays, the caller opens it
again at once, and the new call sends the list and the full sets again. When a
call ends for a different cause, the tenant gets no call on that session; the
next session opens it again. The caller ends a call when the tenant has no
attachments.

The called relay names the tenant of the call by the project of the first VPC
of the first message. It ends the call with `InvalidArgument` when the first
message has no VPC, when a `seq` is not the last one plus 1, when a message is
above a limit, when a VPC list comes after its end, when a part comes before
the end of the list, and when a message has two parts of one VPC. It ends the
call with `PermissionDenied` when a VPC is of another tenant. A new call of a
tenant on a session ends the old one.

An entry has the VPC, the attachment ID, the prefixes (the addresses and the
advertised routes), the SPIFFE ID and the `Hello.name` of the agent, the
sender tag, the `Hello.instance` of the agent, the `rank` of the attach,
`state`, `attached` (the generation of the first entry of the attachment) and
`active_from` (the end of the hold time of the attachment). A later entry of
the attachment with a new state has a higher generation and the same
`attached`. The state is a fact of the sending relay about the attachment. No
entry tells which announcer is active: each relay selects that. The sending
relay gives the sender tag, a number from 1 to 2^24 - 1, to the session of the
agent when the session starts. All attachments of one session have the same
tag, and no other session of the sending relay has it at the same time. The
relay gives a tag again only after all the other tags. `generation` is the
time of the change in Unix milliseconds: the attach or a state change. A
relay sends each generation one time: when the clock is not above the last
generation, the next one is the last one plus 1. A `gone` entry has the
generation of the last entry of the attachment on the call plus 1.

The called relay keeps a record for each entry that it takes. It refuses an
entry with no attachment ID, with an ID of more than 128 bytes or with no
generation. It also refuses an entry without `gone` that has more than 64
prefixes, a VPC that is not the VPC of its part, a network ID above 24 bits, a
subject that is not an agent ID of that VPC, an `attached` above the
generation, an `active_from` that is not a valid time, a sender tag out of
range or a prefix that does not parse. A refused entry does not end the call,
and the refused entries of one part get one warning.

A record lives with its call. A later entry of the attachment replaces it, a
`gone` entry removes it, and the end of the call removes each record of the
call. When the session ends, each of its calls ends, so the routes of the
records go to other announcers at once. A new call sends its full set, and
the records come again. The called relay does not use `end_of_full_set`.

A relay makes routes from the records after the first probe result of the
trunk of their session (see "Trunk"). A record gives a route for each of its
prefixes in its VPC, with the attachment ID as the origin, when this relay
serves the VPC and the network ID of the record is the network ID of the VPC
on this relay. Each such record is an announcer of each of its prefixes,
together with the attachments of this relay, and the selection of "Relay"
gives the active announcer and the order of the standby ones. An attachment
of this relay has no advantage in the selection. When the active announcer
ends, the next one in the order gets the prefix.

Two relays can have different sets for a short time, and then they can select
different announcers. A relay thus gives a packet that comes from another
relay to its own announcer of the prefix, the first one in the order, also
when its active announcer is on another relay.

The relay sends these routes in `RouteDelta`, as it sends its own, to each
session whose `Hello` has no `local_routes_only`. A session with
`local_routes_only` gets the route of a prefix only while the active
announcer is on this relay. A session gets no route for a prefix that an
attachment of its own agent process announces on another relay: the SPIFFE
ID, the agent name and the instance of the record tell. The route goes away
with its record.

### Keys entry of the relay data plane

`PspSaEntry` (`keys.proto`) does not go on the wire. It is the `entry` of a
P4Runtime `ExternEntry` of the `PspSa` extern in `pkg/vpc/relay/dp`, which the
relay control plane writes in process. An RX entry (`PSP_SA_DIRECTION_RX`) has
the key `(direction, spi)`. A TX entry (`PSP_SA_DIRECTION_TX`) has the key
`(direction, port, session, spi)`. A Read gives an empty `key`, and for an RX
entry it gives `packets` and `seq`.

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
| 12 | The answer `REACH_VISIT` of `ResolvePeer`, and `home_relay` in `NoRoute`. | On `REACH_VISIT`, and on a `NoRoute` with `home_relay`, keeps its peer sessions, with the path of the session to the address down: a new peer session of the same agent replaces it. The agent with the lower address opens a visitor session to `home_relay` with `local_routes_only`, calls `Visit`, and opens the peer session there. The agent with the higher address waits 2 s for that peer session, and then visits in the same way if none came. An agent with a peer session to the address on its attached session, with the path up, does not visit. When the two agents visit, the peer session on the relay of the higher address stays. Data goes on a visit in two cases. A visitor session in QUIC mode carries the data for its peers as data frames, each within the datagram limit of the session. A visitor session in PSP mode carries data when the attached session is in PSP mode too and the path probe at the device MTU passes. The agent asks its own relay again at an interval and moves the peer back when the answer is `REACH_LOCAL` or `REACH_TRUNK`. | No duty: it sends `local_routes_only`, so it gets neither. | Answers `ResolvePeer` with `REACH_VISIT` and `home_relay`, and sends `NoRoute` with `home_relay`, when the session is at revision 12 or later, gets the routes of other relays and has an attachment, and the home relay of the address is a member that is down for 3 s or more, did not close with `RESTART`, and gave a relay ID that no other relay of the mesh has. Answers as a relay at revision 11 in each other case. |
| 13 | The PSP packet of an agent between two relays, with no change and with no trunk SA. One SA lane for a trunk. The trunk formats of the revisions 5, 8 and 9 end here, and the duties of a relay in those lines apply only between relays at revision 13 or later. | When `RegisterSPI` returns `AlreadyExists` for rows that it has, closes the peer session, so that the next peer session has new SAs. | No duty. | Has a trunk only with a relay at revision 13 or later: makes no `TrunkKeys` call and no `SPIRows` call to an older relay, refuses those calls of it with `FailedPrecondition`, sends it no packet of a sender, answers no `REACH_TRUNK` for it, and keeps that session. Sends the PSP packet of a row to another relay with no change, and seals only clear inner packets and its own messages with the trunk SA. For a packet from the address of a member: opens it when a trunk SA for that member has its SPI, sends it with no change to a session of its own when a row of that member has its SPI, and drops it in each other case. Keeps each SPI in one use for the packets to a member: refuses `RegisterSPI` with `AlreadyExists`, ends a row that goes to a member with its SPI in use, and returns a trunk SA with the SPI of a row in `refused_spis`. |
| 14 | `Mesh.Snapshot`. | No duty. | No duty. | Answers `Snapshot` on the open mesh session of a member with the snapshot of its host, in parts of at most 1 MiB with `total_size` in the first part. Answers `NotFound` when its host gives no snapshot, and `ResourceExhausted` for a snapshot above 64 MiB. Calls `Snapshot` only when its host asks for a snapshot, and only on a member at revision 14 or later, with 10 s for each member. Takes no snapshot with a `total_size` of 0 or above 64 MiB, or with a number of bytes that is not `total_size`. |
| 15 | More than one `Visit` call on a visitor session. `Detach` on a visitor session. | After the first `Visit` call on a relay at revision 15 or later, makes one `Visit` call for each address prefix of each extra attachment of its attached session, with the grant of that attachment, and sends those grants in `Peer.Open` and in `Grants` on the visitor session. Does the same for an attachment that it adds during the visit. Calls `Detach` on the visitor session with the ID of an attachment that it removes during the visit. On a relay below revision 15, makes one `Visit` call, so the peers of the visit reach only the address of the first attachment. | No duty. | Accepts a `Visit` call on a visitor session when the grant is of the same home relay: the session gets one more visit prefix, or the new grant for a prefix that it has. Keeps at most 64 visit prefixes on a session, and answers `ResourceExhausted` above that. The limit of 2 visitor sessions of an agent counts sessions, not prefixes. Ends each visit prefix alone: at the end of its grant, when the address gets another owner, and on a `Detach` call of the visitor with the attachment ID of the grant. A relay below revision 15 answers the second `Visit` call with `FailedPrecondition` and such a `Detach` call with `NotFound`. |
| 16 | A set of announcers for each prefix, with one selection. `Hello.instance`, `AttachRequest.rank`, `AttachResponse.routes`, `Route.standby`, and `instance`, `rank`, `state`, `attached` and `active_from` in a presence entry. The states `DRAINING` and `SUSPECT`, and the hold time of 30 s. | Sends its instance in `Hello`, and sends `Hello` before `Attach`. Attaches on each of its relay connections, with the rank of the connection in `AttachRequest.rank`. Accepts the statuses in `AttachResponse` and the standby list of a route. When the active announcer of a prefix changes, gets a remove and an add, and closes the peer session to the old announcer, as for each removed route. Sends a QUIC keep-alive each 3 s. | No duty. | Keeps each attachment that lists a prefix as an announcer of it, and selects the active one with the rules of "Relay". Does not refuse an `Attach` because another agent announces the route. Checks each advertised route of an `Attach`, and refuses a default route, an IPv4-mapped IPv6 prefix and a prefix that overlaps the network of the VPC. A refused route does not fail the `Attach`: it has a result that is not `ROUTE_RESULT_ACCEPTED` in `AttachResponse.routes`, and the attachment is not an announcer of it. An agent below revision 16 gets no statuses. Refuses an `Attach` before `Hello` with `FailedPrecondition`. Lets each announcer of a prefix send from it, and no other session. Sends the standby list only to a session at revision 16 or later: an older agent gets one announcer for each prefix. Sends a QUIC keep-alive on an agent connection after 2 s with no packet, and gives the attachments of a session the state `SUSPECT` after 6 s with no packet of the agent, and `NORMAL` again after 4 s with packets. Gives all its attachments the state `DRAINING` at the start of a drain, before `Drain`. Sends an entry with a higher generation, the same `attached` and `active_from` for each state change, and applies such an entry in place, with no remove of its routes. Reads each entry of a lost member as `SUSPECT`, and drops the entries of a member that is still down after 5 minutes. Selects a `NORMAL` announcer in its hold time after each `NORMAL` announcer out of it, and, when each one is in its hold time, the one with the earliest `active_from` first. Reads the entry of a relay below revision 16 as instance 0, rank 0, state `NORMAL` and no hold time. A relay below revision 16 keeps one attachment for each prefix: it refuses the `Attach` of a second agent with `AlreadyExists`, and it prefers its own attachment. In a mesh with both kinds of relay, two relays can thus select different announcers for a prefix. Each relay gives a packet from another relay to its own announcer of the prefix, so such a packet does not drop. |
| 17 | `Relay.Grant`. A visit with no time limit. | Before it sends a grant in `Open`, `Grants` or `Visit`, gets a new one with `Grant` when it got its stored grant 5 minutes ago or earlier, on the session that has the attachment. Sends each grant one time: no new grant goes to an open peer session or to a visit. | No duty. | Answers `Grant` with a new grant for an attachment of the session of the caller, which ends 15 minutes after the call, as the grant of `Attach` does, and with `NotFound` for each other attachment ID and for a visitor session. Checks `not_after` of a grant one time, at the `Visit` call, and does not end a visit when it passes. A relay below revision 17 answers `Grant` with `Unimplemented`, and it ends a visit at `not_after` of its grant. |
| 18 | The change of an open session from QUIC mode to PSP mode with `Rekey`. Data frames from a session in each mode. `Welcome.max_lanes` in each mode. | After two PSP probes pass on a session in QUIC mode, calls `Rekey` on a relay at revision 18 or later, sends PSP packets when it has the relay SAs, and closes the peer sessions of that relay session. Opens no new session for PSP mode. On a relay below revision 18, makes no such `Rekey` call and stays in QUIC mode. | No duty. | Accepts `Rekey` on a session in QUIC mode and changes the session to PSP mode, as in "Data mode". Takes data frames from a session in each mode. Sends its lane port limit in `Welcome.max_lanes` in each mode. A relay below revision 18 answers that `Rekey` with `FailedPrecondition`, drops the data frames of a PSP-mode session, and sends `max_lanes` 0 to a session in QUIC mode. |
| 19 | `Welcome.psp_host` and `Welcome.psp_port`, and the same two fields in `MeshOpenRequest` and `MeshOpenResponse`. The `Moved` message is gone. The counter of a path probe, and probe version 2. A QUIC socket and a PSP socket on each relay. | Starts each session in QUIC mode. After `Welcome`, sends its path probes, with a counter that grows, to the PSP socket of the relay (`Welcome.psp_host`, or the host that it dialed when that is empty, at `Welcome.psp_port`), and calls `Rekey` when a probe passes. Sends its PSP packets and lane keep-alives to that address. In PSP mode, sends a probe each 5 s. Sends no probe before `Hello` and opens no new session for PSP mode. | No duty. | Reads QUIC on one socket and drops each other packet there. Reads PSP packets, probes, lane keep-alives and the packets of other relays on its PSP socket, and sends to another relay at the PSP socket that this relay gave in `Open`. Sends `psp_host` empty and `psp_port` with the local port of its PSP socket in `Welcome` and in `Open`. Starts each session in QUIC mode, also for a `Hello` with PSP mode, and sends no relay SAs after `Config`. Takes the PSP address of a session from the path probe with the largest counter, when its IP address is that of the QUIC connection. Keeps no probe that comes before its session. The two sides must be at revision 19: there is no code for an older agent or relay. |
| 20 | The BFD packet in a path probe, with the probe flag `0x02`. The change of an open session from PSP mode to QUIC mode. | In PSP mode, sends a BFD packet to the PSP socket of the relay each 2 s, in place of the probe each 5 s, and at each change of its state. Changes the session to QUIC mode when the PSP path is lost, as in "PSP path check", and probes with backoff for the return to PSP mode. | No duty. | Runs one BFD session for each session in PSP mode, sends its BFD packets to the PSP address of the session, and sends no reply to a probe with a BFD packet. Changes the session to QUIC mode when the PSP path is lost, as in "PSP path check", and takes a later `Rekey` as on each session in QUIC mode. The two sides must be at revision 20: there is no code for an older agent or relay. |
| 21 | `Relay.ResolvePeer`, `RegisterSPI`, `UnregisterSPI`, `Visit` and `Grant`, the `Peer` service (`apoxy-peer/1`), `AttachmentGrant` and `GrantClaims` are gone; `AttachResponse.grant` and `NoRoute.home_relay` are reserved. `Welcome.relay_id`, `Route.relay`, `AttachResponse.addresses`, `RemoteAddresses` and `KeysRequest.generation`. `ROUTE_RESULT_IPV4`. A Route for each slot. The first route table in parts. The minimum revision of each side is 21. | Opens no peer session and makes none of the removed calls. Sends the number of its key attempt in `KeysRequest.generation` of each `Rekey` that changes the mode. Takes the first route table in `RouteDelta` parts, up to the first one with no routes. | No duty. | Answers the removed calls with `Unimplemented`. Sends its ID in `Welcome.relay_id`, the `RelayRef` of the relay of the origin in `Route.relay`, and the addresses of an attachment in `AttachResponse.addresses`. Copies `generation` of the `Rekey` that changes the mode into its `OfferSAs`. Refuses each IPv4 prefix that is not a default route with `ROUTE_RESULT_IPV4`. Sends one Route for each /88 slot of the network of the VPC in place of the /96 routes of its attachments, with the ID of the relay that holds the slot as its origin. Sends the first route table in `RouteDelta` parts of at most 256 routes and 1 MiB, then one `RouteDelta` with no routes. Closes a session below revision 21 with `UPGRADE`. |
| 22 | `Mesh.Presence` is a bidirectional call, one for each tenant and direction, with `PresenceUpdate{seq, vpcs, end_of_vpcs, parts}`, `PresencePart` and `PresenceControl{ack}`; `PresenceUpdate` fields 1 and 2 (`entries`, `end_of_full_set`) are reserved. `Mesh.SPIRows` and `SPIRowUpdate` are gone. A record lives with its call. Each packet between two relays is a trunk packet. The minimum revision of a relay on a mesh session is 22. | No duty. | No duty. | Opens one `Presence` call for each tenant with attachments on each mesh session, with the flow control and the limits of "Mesh", ends a call that has a message with no ack for 5 s and opens it again, and opens no new call of a tenant whose call ended for a different cause until the next session. Keeps the records of a call until the call ends, and deletes the records and the trunk SAs of a member at once when its session ends. Makes the routes of a member after the first probe result of its trunk. Takes a trunk packet only from the PSP socket that the member gave in `Open`, and refuses a member that gives no PSP port. With a mesh, refuses an `Attach` with more than 64 prefixes, or whose entry does not fit in one `PresenceUpdate`. Closes a mesh session with a relay below revision 22 with `UPGRADE`. |

### Minimum revision

Each side has a minimum for the revision of the other side. A relay takes an
agent at revision 21 or later, and another relay of its mesh at revision 22
or later. It closes a mesh session below that with the `MeshCloseCode`
`UPGRADE`.

- A relay closes a session below its minimum with the `RelayCloseCode`
  `UPGRADE`, and the close reason gives the minimum. When no other relay takes
  the agent, the agent stops its dial loop and returns an error that tells the
  user to upgrade.
- An agent that finds a relay below its minimum closes the session and dials
  the next relay.
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
curl -d '{"vpc":{"project_id":"p-1","vpc_uid":"u-1","network_id":658188},"name":"laptop"}' \
  http://127.0.0.1:8081/apoxy.vpc.datapath.v1.Relay/Attach
```
