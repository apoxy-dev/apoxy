module github.com/apoxy-dev/apoxy/cmd/tunbench

go 1.26.8

// The default build uses the same quic-go fork and gvisor fork as the apoxy
// module. stock.mod drops the quic-go replace (build it with -tags stock).
replace github.com/quic-go/quic-go => github.com/apoxy-dev/quic-go v0.0.0-20260402225711-bc93b3ff7555

replace gvisor.dev/gvisor => github.com/apoxy-dev/gvisor v0.0.0-20260717065740-69bda9ac252c

require (
	github.com/apoxy-dev/icx v0.19.1-0.20260826222334-295d1c74aeae
	github.com/quic-go/quic-go v0.59.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/net v0.55.0
	gvisor.dev/gvisor v0.0.0-20260421223920-580553b31b48
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/phemmer/go-iptrie v0.0.0-20240326174613-ba542f5282c9 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
