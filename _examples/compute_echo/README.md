# Compute Service echo demo (APO-796)

The workerd-runtime analogue of the EdgeFunction example
(`../httproute_edgefunc.yaml`). An `HTTPRoute` routes to a
`compute.apoxy.dev` `Service` backendRef; the apiserver mints a
`ServiceRevision` from `spec.source`, the co-located **workerd-manager** loads
it into the one shared resident workerd as a V8 isolate, and the backplane
demuxes inbound requests to it via the `x-apoxy-service` header.

Files here:

- `echo.js` — the worker (ES module; entrypoint). Echoes the request as JSON.
- `manifest.json` — the `BundleManifest` (OCI config blob) listing the modules
  and the workerd compatibility date.
- `../httproute_compute_echo.yaml` — the Proxy/Gateway/HTTPRoute + `Service`.

## 1. Build and push the echo OCI bundle

A service bundle is a plain OCI artifact: the config blob is the
`BundleManifest` JSON, and an `esModule`/`commonJsModule`/… layer carries the
module files (a gzip tar keyed by each `Module.Path`). Build it with
[`oras`](https://oras.land):

```bash
cd _examples/compute_echo

# Modules layer: a gzip tar whose entries match manifest.json Module.Path.
tar czf modules.tar.gz echo.js

# Push the artifact. ttl.sh is an anonymous ephemeral registry good for a demo;
# swap in your own repo for anything lasting.
oras push ttl.sh/apoxy-examples-echo:latest \
  --config manifest.json:application/vnd.apoxy.dev.service.config.v1+json \
  modules.tar.gz:application/vnd.apoxy.dev.service.modules.v1.tar+gzip
```

The media types are fixed (see `api/compute/v1alpha1/bundle_types.go`):

| Part         | Media type                                                  |
|--------------|-------------------------------------------------------------|
| config blob  | `application/vnd.apoxy.dev.service.config.v1+json`          |
| modules      | `application/vnd.apoxy.dev.service.modules.v1.tar+gzip`     |
| assets (opt) | `application/vnd.apoxy.dev.service.assets.v1.tar+gzip`      |

Point `spec.source.oci.repo`/`tag` in `../httproute_compute_echo.yaml` at the
repo you pushed (pin a `digest` for anything but a throwaway demo).

## 2. Run under `apoxy dev`

```bash
apoxy dev _examples/httproute_compute_echo.yaml
curl -s -H 'Host: echo.example.com' http://localhost:10000/hello
```

Expected: the JSON echo of your request (method, path, query, headers, body).

## Status / prerequisites not yet automated

The control-plane half works today: applying the `Service` mints a
`ServiceRevision`, and the backplane data plane (resident cluster injection +
`x-apoxy-service` demux) is wired in the apiserver (APO-796 P4). The end-to-end
run additionally needs, and these are the remaining gaps:

1. **A stock workerd OCI image** (`--workerd_image`), linux/arm64 for Apple
   Silicon Docker. The manager pulls it via clrk's image store; none is
   published yet. (P3)
2. **A workerd-manager driver in `apoxy dev`** that runs the privileged/runsc
   manager next to the backplane, shares the resident socket with the
   backplane's Envoy, and publishes routing to the apiserver's
   `--workerd_publish_addr`. (P5)
3. **Dev images built on the clrk control-forwarder pin** (clrk `a4ce619`): the
   resident dispatcher reaches the manager through clrk's guest→host control
   forwarder, which must be in the manager image.

Until those land, this directory documents the intended bundle + manifest and
the example wiring; `curl` will return `503` (the route's placeholder backend)
because no resident is published.
