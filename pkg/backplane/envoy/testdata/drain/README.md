Real Envoy v1.35.13 admin responses (`envoyproxy/envoy:v1.35.13`,
`--concurrency 4 --drain-time-s 600`, file-based LDS). Listeners: `http-10080`
(HCM, `stat_prefix: http`, codec AUTO) and `tcp-10443` (tls_inspector +
tcp_proxy to the HTTP listener). One idle admin connection is open in every
capture.

- `*.stats.json`: `/stats?format=json&filter=downstream_(rq_active|rq_total|cx_active|pre_cx_active|cx_tx_bytes_buffered)$`
- `*.config_dump.json`: `/config_dump?resource=dynamic_listeners`

| Name | State |
|---|---|
| `mixed_idle` | HTTP/1.1 and HTTP/2 requests served, all client connections closed |
| `mixed_busy` | one idle HTTP/1.1 connection, one tcp_proxy connection, one connection stuck in tls_inspector |
| `replaced_busy` | `mixed_busy` after an LDS update of `per_connection_buffer_limit_bytes` on `http-10080` (active + draining) |
| `replaced_idle` | `replaced_busy` after every client connection closed |
| `h1only_draining` | fresh Envoy, HTTP/1.1 only, after `healthcheck/fail` and `drain_listeners?graceful&skip_exit` |
| `ready_probed_a`, `ready_probed_b` | the same listeners plus the bootstrap's static readiness listener (`envoy-gateway-proxy-ready-0.0.0.0-19001`, `stat_prefix: eg-ready-http`, rendered by `bootstrap.GetRenderedBootstrapConfig`), drained as above, with `GET :19001/ready` every 0.5s; captured 3s apart (`http.eg-ready-http.downstream_rq_total` 5, then 11) |
| `udp_session` | the `ready_probed` listeners plus `udp-10053` (UDP, `udp_listener_config`, udp_proxy `stat_prefix: udp` to a static UDP cluster); one HTTP request served and closed, one UDP datagram sent (`udp.udp.downstream_sess_active` 1), then drained as above |
