// Apoxy workerd resident dispatcher. DO NOT EDIT (embedded into the resident
// workerd config by BuildResidentConfig).
//
// This is the single static worker that fronts the one resident workerd. It
// demuxes each inbound request to the right customer isolate by the
// `x-apoxy-service` header (value = "<project>:<service>:<revision>", set by the
// backplane; project-qualified so two projects' same-named services never share
// an isolate on the shared resident), dynamically loading that isolate from the
// manager via the WorkerLoader binding. Isolates are cached by id; a new revision is a new id,
// so make-before-break is just the backplane flipping the header to the new
// revision and the old isolate idling out (workerd auto-evicts unused isolates).
const SERVICE_HEADER = "x-apoxy-service";
const HEALTH_PATH = "/__apoxy/health";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // Readiness probe: answerable without a loaded isolate, so the manager can
    // gate the resident before any service is live.
    if (url.pathname === HEALTH_PATH) {
      return new Response("ok\n", { status: 200 });
    }

    const id = req.headers.get(SERVICE_HEADER);
    if (!id) {
      return new Response("apoxy: missing " + SERVICE_HEADER + " header\n", { status: 400 });
    }

    // WorkerLoader.get caches the isolate by id. On a cache miss the callback
    // runs and fetches the worker definition from the manager over the MANAGER
    // binding (an external HTTP service). In production its address is an
    // in-sandbox TCP target that clrk's guest->host control forwarder splices to
    // the host ServiceManager's control socket (clrk has no host-UDS, so this is
    // not a unix socket from the guest's side).
    const worker = env.LOADER.get(id, async () => {
      const res = await env.MANAGER.fetch(
        "http://manager/worker?id=" + encodeURIComponent(id),
      );
      if (!res.ok) {
        throw new Error("apoxy: manager returned " + res.status + " for " + id);
      }
      const def = await res.json();
      return {
        compatibilityDate: def.compatibilityDate,
        compatibilityFlags: def.compatibilityFlags || [],
        mainModule: def.mainModule,
        modules: def.modules,
        env: def.env || {},
        // M1: customer egress is not yet mediated; deny by default.
        globalOutbound: null,
      };
    });

    return await worker.getEntrypoint().fetch(req);
  },
};
