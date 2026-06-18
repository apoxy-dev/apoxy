// echo.js — a minimal Apoxy compute Service (APO-796) worker.
//
// It is a stock-workerd ES module: the resident dispatcher loads it as a
// WorkerLoader isolate (demuxed by the x-apoxy-service header the backplane
// sets) and forwards each request to this fetch handler. The handler echoes the
// request back as JSON so the end-to-end data path is easy to eyeball.
//
// This is the entrypoint module referenced by manifest.json (the first esModule
// in a bundle is the entrypoint). It is packaged into an OCI service bundle and
// served via spec.source.oci on the echo Service — see README.md.
export default {
  async fetch(req) {
    const url = new URL(req.url);
    const body = await req.text();
    const payload = {
      service: "echo",
      method: req.method,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      headers: Object.fromEntries(req.headers),
      body,
    };
    return new Response(JSON.stringify(payload, null, 2) + "\n", {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
};
