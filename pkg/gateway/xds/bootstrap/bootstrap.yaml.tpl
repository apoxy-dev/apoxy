admin:
  access_log:
  - name: envoy.access_loggers.file
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
      path: {{ .AdminServer.AccessLogPath }}
  address:
    socket_address:
      address: {{ .AdminServer.Address }}
      port_value: {{ .AdminServer.Port }}
{{- if .StatsMatcher  }}
stats_config:
  stats_matcher:
    inclusion_list:
      patterns:
      {{- range $_, $item := .StatsMatcher.Exacts }}
      - exact: {{$item}}
      {{- end}}
      {{- range $_, $item := .StatsMatcher.Prefixs }}
      - prefix: {{$item}}
      {{- end}}
      {{- range $_, $item := .StatsMatcher.Suffixs }}
      - suffix: {{$item}}
      {{- end}}
      {{- range $_, $item := .StatsMatcher.RegularExpressions }}
      - safe_regex:
          google_re2: {}
          regex: {{js $item}}
      {{- end}}
{{- end }}
layered_runtime:
  layers:
  - name: global_config
    static_layer:
      envoy.restart_features.use_eds_cache_for_ads: true
      re2.max_program_size.error_level: 4294967295
      re2.max_program_size.warn_level: 1000
dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
    - envoy_grpc:
        cluster_name: xds_cluster
    set_node_on_first_message_only: true
  lds_config:
    ads: {}
    resource_api_version: V3
  cds_config:
    ads: {}
    resource_api_version: V3

{{- if .OtelMetricSinks }}
stats_sinks:
{{- range $idx, $sink := .OtelMetricSinks }}
- name: "envoy.stat_sinks.open_telemetry"
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.stat_sinks.open_telemetry.v3.SinkConfig
    grpc_service:
      envoy_grpc:
        cluster_name: otel_metric_sink_{{ $idx }}
{{- end }}
{{- end }}

static_resources:
  listeners:
  - name: envoy-gateway-proxy-ready-{{ .ReadyServer.Address }}-{{ .ReadyServer.Port }}
    address:
      socket_address:
        address: {{ .ReadyServer.Address }}
        port_value: {{ .ReadyServer.Port }}
        protocol: TCP
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: eg-ready-http
          route_config:
            name: local_route
            {{- if .EnablePrometheus }}
            virtual_hosts:
            - name: prometheus_stats
              domains:
              - "*"
              routes:
              - match:
                  prefix: /stats/prometheus
                route:
                  cluster: prometheus_stats
            {{- end }}
          http_filters:
          - name: envoy.filters.http.health_check
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.health_check.v3.HealthCheck
              pass_through_mode: false
              headers:
              - name: ":path"
                string_match:
                  exact: {{ .ReadyServer.ReadinessPath }}
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  {{- if .EnablePrometheus }}
  - name: prometheus_stats
    connect_timeout: 0.250s
    type: STATIC
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: prometheus_stats
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {{ .AdminServer.Address }}
                port_value: {{ .AdminServer.Port }}
  {{- end }}
  {{- range $idx, $sink := .OtelMetricSinks }}
  - name: otel_metric_sink_{{ $idx }}
    connect_timeout: 0.250s
    type: STRICT_DNS
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
        explicit_http_config:
          http2_protocol_options: {}
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: otel_metric_sink_{{ $idx }}
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {{ $sink.Address }}
                port_value: {{ $sink.Port }}
  {{- end }}
  - name: xds_cluster
    connect_timeout: 10s
    type: STRICT_DNS
    dns_lookup_family: V4_ONLY
    load_assignment:
      cluster_name: xds_cluster
      endpoints:
      - load_balancing_weight: 1
        lb_endpoints:
        - load_balancing_weight: 1
          endpoint:
            address:
              socket_address:
                address: {{ .XdsServer.Address }}
                port_value: {{ .XdsServer.Port }}
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions"
        explicit_http_config:
          http2_protocol_options:
            connection_keepalive:
              interval: 30s
              timeout: 5s
overload_manager:
  refresh_interval: 0.25s
  resource_monitors:
  - name: "envoy.resource_monitors.global_downstream_max_connections"
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig
      max_active_downstream_connections: {{ .OverloadManager.MaxActiveDownstreamConnections }}
  {{- with .OverloadManager.MaxHeapSizeBytes }}
  - name: "envoy.resource_monitors.fixed_heap"
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.resource_monitors.fixed_heap.v3.FixedHeapConfig
      max_heap_size_bytes: {{ . }}
  actions:
  - name: "envoy.overload_actions.shrink_heap"
    triggers:
    - name: "envoy.resource_monitors.fixed_heap"
      threshold:
        value: 0.95
  - name: "envoy.overload_actions.stop_accepting_requests"
    triggers:
    - name: "envoy.resource_monitors.fixed_heap"
      threshold:
        value: 0.98
  {{- end }}