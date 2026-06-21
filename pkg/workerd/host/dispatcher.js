// Apoxy workerd resident dispatcher. DO NOT EDIT (embedded into the resident
// workerd config by BuildResidentConfig).
//
// This is the single static worker that fronts the one resident workerd. The
// backplane stamps `x-apoxy-service: <project>:<service>` (project-qualified so
// two projects' same-named services never share an isolate on the shared
// resident) and routes here. The dispatcher resolves that service to its live
// revision id via the manager's /resolve endpoint, then dynamically loads (and
// caches) that isolate from the manager via the WorkerLoader binding.
//
// The revision lives entirely in the resident now — it is never stamped into
// Envoy config, so a rollout is invisible to xDS. Isolates are still cached by
// the revision-bearing id, so make-before-break is unchanged: a new revision is a
// new id, a new isolate loads while the old one idles out (workerd auto-evicts).
const SERVICE_HEADER = "x-apoxy-service";
const HEALTH_PATH = "/__apoxy/health";

// resolveCache memoizes "<project>:<service>" -> { id, expiry } so the steady-state
// hot path makes no extra control round trip: a cached id hits the cached isolate
// directly. The TTL bounds how long a node keeps routing to a just-rolled revision
// after a flip; both isolates coexist within the window, so a stale read is
// make-before-break, not an error.
const RESOLVE_TTL_MS = 1000;
// On a transient /resolve failure we keep serving the last-known id but re-arm a
// short negative TTL, so a degraded control channel sees at most one probe per
// window instead of one per inbound request (an expired entry would otherwise
// stampede the failing endpoint with the full request rate).
const RESOLVE_FAIL_TTL_MS = 250;
const resolveCache = new Map();
// inflightResolves coalesces concurrent cold/expired resolves for the same service
// into one control round trip (a cold or just-expired popular service would
// otherwise stampede the control channel).
const inflightResolves = new Map();

async function resolveID(env, service) {
  const hit = resolveCache.get(service);
  if (hit && hit.expiry > Date.now()) {
    return hit.id;
  }
  let inflight = inflightResolves.get(service);
  if (!inflight) {
    inflight = fetchID(env, service, hit).finally(() => inflightResolves.delete(service));
    inflightResolves.set(service, inflight);
  }
  return await inflight;
}

// fetchID resolves a service to its live revision id over the control channel,
// distinguishing the manager's authoritative answers from transient failures:
//   - a 4xx ("no live revision": last revision deleted/unpinned) is authoritative
//     — drop any stale entry and return null so the caller surfaces 503;
//   - a 5xx, a connection-level throw, or a malformed/idless body is transient —
//     keep serving the last known revision (if any) rather than dropping traffic.
async function fetchID(env, service, hit) {
  let res;
  try {
    res = await env.MANAGER.fetch(
      "http://manager/resolve?service=" + encodeURIComponent(service),
    );
  } catch (e) {
    return staleOrNull(service, hit);
  }
  if (res.status >= 400 && res.status < 500) {
    resolveCache.delete(service);
    return null;
  }
  if (!res.ok) {
    return staleOrNull(service, hit);
  }
  let body;
  try {
    body = await res.json();
  } catch (e) {
    return staleOrNull(service, hit);
  }
  if (!body || !body.id) {
    // A 2xx without a usable id is a malformed answer: treat it as transient
    // rather than caching an undefined id (which would 503 the service for a full
    // TTL with no re-probe).
    return staleOrNull(service, hit);
  }
  resolveCache.set(service, { id: body.id, expiry: Date.now() + RESOLVE_TTL_MS });
  return body.id;
}

// staleOrNull serves the last-known id on a transient failure, re-arming a short
// negative TTL so a degraded control channel sees one probe per window, not one
// per request. Returns null when nothing is known to serve (-> caller 503s).
function staleOrNull(service, hit) {
  if (!hit) {
    return null;
  }
  resolveCache.set(service, { id: hit.id, expiry: Date.now() + RESOLVE_FAIL_TTL_MS });
  return hit.id;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // Readiness probe: answerable without a loaded isolate, so the manager can
    // gate the resident before any service is live.
    if (url.pathname === HEALTH_PATH) {
      return new Response("ok\n", { status: 200 });
    }

    const service = req.headers.get(SERVICE_HEADER);
    if (!service) {
      return new Response("apoxy: missing " + SERVICE_HEADER + " header\n", { status: 400 });
    }

    // Resolve the project-qualified service to its live revision id. The backplane
    // routes here only once a revision is live, so a miss is a brief rollout-edge
    // window: surface 503 so the client retries rather than caching a bad id.
    const id = await resolveID(env, service);
    if (!id) {
      return new Response("apoxy: no live revision for " + service + "\n", { status: 503 });
    }

    // WorkerLoader.get caches the isolate by id. On a cache miss the callback runs
    // and fetches the worker definition from the manager over the MANAGER binding
    // (an external HTTP service). In production its address is an in-sandbox TCP
    // target that clrk's guest->host control forwarder splices to the host
    // ServiceManager's control socket (clrk has no host-UDS, so this is not a unix
    // socket from the guest's side).
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
