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

QUIC datagrams and PathProbe packets on the same socket are not part of this
document.

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
| `Session`       | bidi  | Agent: `Hello`, then `Ack{rev}` and `Status` (ICV failures). Relay: `Welcome` (reflexive address), then `RouteDelta{rev}`, `NoRoute`, rekey (`KeysRequest`), `Config`, `Drain`. |
| `Attach`        | unary | `AttachRequest{vpc, name, labels, routes}` -> `AttachResponse{attachment_id, grant}` |
| `Rekey`         | unary | `KeysRequest` -> `KeysResponse`: SAs for traffic from the relay to the agent. |
| `ResolvePeer`   | unary | `{vpc, address}` -> `{reach: local, trunk or visit; home_relay; p2p}`. Errors: `NotFound`, `PermissionDenied`. |
| `RegisterSPI`   | unary | `{vpc, destination, spis, expires_in}` -> `Empty` |
| `UnregisterSPI` | unary | `{vpc, spis}` -> `Empty` |

### Peer (`apoxy-peer/1`)

| Method  | Kind          | Messages |
|---------|---------------|----------|
| `Open`  | unary         | Dialer and listener each send `{grant, instance, mode, p2p}`. First call on a session. |
| `Keys`  | unary         | The receiver sends `KeysRequest`: `OfferSAs`, `RekeySA` or `RevokeSA`. `KeysResponse` lists SPIs that the sender refuses. |
| `Paths` | client stream | `Candidates{round, candidates, mtu}`; each agent calls it. |

An agent closes a peer session with a `PeerCloseCode`: `DUPLICATE` or
`BAD_GRANT`.

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
