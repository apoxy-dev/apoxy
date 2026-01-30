// main-service.ts - Apoxy Edge Runtime Main Service
//
// This service runs as the main worker in edge-runtime and manages:
// - Function registry and worker lifecycle
// - Control plane endpoints (/_internal/*)
// - Request routing via x-function-id header
// - Prometheus metrics

console.log("main function started");
console.log(Deno.version);

addEventListener("beforeunload", () => {
  console.log("main worker exiting");
});

addEventListener("unhandledrejection", (ev) => {
  console.log(ev);
  ev.preventDefault();
});

// --- Configuration ---

const WORKER_MEMORY_LIMIT_MB = parseInt(
  Deno.env.get("WORKER_MEMORY_LIMIT_MB") ?? "256",
);
const WORKER_TIMEOUT_MS = parseInt(
  Deno.env.get("WORKER_TIMEOUT_MS") ?? "300000",
);
const CPU_TIME_SOFT_LIMIT_MS = parseInt(
  Deno.env.get("CPU_TIME_SOFT_LIMIT_MS") ?? "10000",
);
const CPU_TIME_HARD_LIMIT_MS = parseInt(
  Deno.env.get("CPU_TIME_HARD_LIMIT_MS") ?? "20000",
);
const IDLE_TIMEOUT_MS = parseInt(
  Deno.env.get("IDLE_TIMEOUT_MS") ?? "300000",
);

// --- Function Registry ---

interface FunctionEntry {
  functionId: string;
  functionName: string;
  eszipPath: string;
  eszipBytes: Uint8Array;
  worker: any | null;
  ready: boolean;
  lastRequest: number;
}

const functions = new Map<string, FunctionEntry>();

// --- Metrics State ---

const requestCounts = new Map<string, Map<number, number>>(); // function_id -> status -> count
const requestDurations: number[] = []; // all request durations in seconds
let coldStartsTotal = 0;

// --- Worker Creation ---

async function createWorkerForFunction(
  entry: FunctionEntry,
): Promise<any> {
  const envVarsObj = Deno.env.toObject();
  const envVars = Object.keys(envVarsObj).map((k) => [k, envVarsObj[k]]);

  return await EdgeRuntime.userWorkers.create({
    servicePath: entry.functionId,
    maybeEszip: entry.eszipBytes,
    maybeEntrypoint: "file:///src/index.ts",
    memoryLimitMb: WORKER_MEMORY_LIMIT_MB,
    workerTimeoutMs: WORKER_TIMEOUT_MS,
    cpuTimeSoftLimitMs: CPU_TIME_SOFT_LIMIT_MS,
    cpuTimeHardLimitMs: CPU_TIME_HARD_LIMIT_MS,
    noModuleCache: false,
    envVars,
    forceCreate: true,
    context: {
      useReadSyncFileAPI: true,
    },
  });
}

// --- Background: Idle Cleanup ---

setInterval(() => {
  const now = Date.now();
  for (const [fnId, entry] of functions) {
    if (
      entry.ready &&
      entry.worker &&
      entry.lastRequest > 0 &&
      now - entry.lastRequest > IDLE_TIMEOUT_MS
    ) {
      console.log(`idle cleanup: releasing worker for ${fnId}`);
      entry.worker = null;
      entry.ready = false;
    }
  }
}, 30_000);

// --- HTTP Server ---

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const { pathname } = url;

  // ─── Control Plane ───

  if (pathname === "/_internal/upload" && req.method === "POST") {
    try {
      const body = await req.json();
      const { function_id, function_name, eszip_path } = body;

      if (!function_id || !eszip_path) {
        return Response.json(
          { error: "function_id and eszip_path are required" },
          { status: 400 },
        );
      }

      const eszipBytes = await Deno.readFile(eszip_path);

      functions.set(function_id, {
        functionId: function_id,
        functionName: function_name ?? function_id,
        eszipPath: eszip_path,
        eszipBytes,
        worker: null,
        ready: false,
        lastRequest: 0,
      });

      console.log(
        `uploaded function ${function_id} (${function_name}) from ${eszip_path}`,
      );
      return Response.json({ uploaded: function_id });
    } catch (e) {
      console.error("upload error:", e);
      return Response.json({ error: e.message }, { status: 400 });
    }
  }

  if (pathname === "/_internal/ready" && req.method === "POST") {
    try {
      const body = await req.json();
      const { function_id } = body;

      const entry = functions.get(function_id);
      if (!entry) {
        return Response.json(
          { ready: false, error: "function not found" },
          { status: 404 },
        );
      }

      const start = performance.now();
      try {
        entry.worker = await createWorkerForFunction(entry);
        entry.ready = true;
        coldStartsTotal++;
        const coldStartMs = Math.round(performance.now() - start);

        console.log(
          `function ${function_id} ready (cold start: ${coldStartMs}ms)`,
        );
        return Response.json({ ready: true, cold_start_ms: coldStartMs });
      } catch (e) {
        console.error(`function ${function_id} failed to start:`, e);
        return Response.json(
          { ready: false, error: e.message },
          { status: 503 },
        );
      }
    } catch (e) {
      return Response.json({ error: e.message }, { status: 400 });
    }
  }

  if (pathname === "/_internal/health") {
    const funcs: Record<string, object> = {};
    for (const [id, entry] of functions) {
      funcs[id] = {
        ready: entry.ready,
        loaded: entry.eszipBytes != null,
        last_request_ms: entry.lastRequest > 0
          ? Date.now() - entry.lastRequest
          : null,
      };
    }
    return Response.json({ status: "ok", functions: funcs });
  }

  if (
    pathname.startsWith("/_internal/functions/") && req.method === "DELETE"
  ) {
    const fnId = pathname.split("/")[3];
    if (!fnId) {
      return Response.json(
        { error: "function_id is required" },
        { status: 400 },
      );
    }

    const existed = functions.delete(fnId);
    if (existed) {
      console.log(`deleted function ${fnId}`);
    }
    return new Response(null, { status: 204 });
  }

  if (pathname === "/_internal/metrics") {
    const lines: string[] = [];

    // Gauge: total functions
    lines.push("# HELP edge_runtime_functions_total Total registered functions");
    lines.push("# TYPE edge_runtime_functions_total gauge");
    lines.push(`edge_runtime_functions_total ${functions.size}`);

    // Gauge: ready functions
    const readyCount = [...functions.values()].filter((e) => e.ready).length;
    lines.push("# HELP edge_runtime_functions_ready Functions with ready workers");
    lines.push("# TYPE edge_runtime_functions_ready gauge");
    lines.push(`edge_runtime_functions_ready ${readyCount}`);

    // Counter: requests total (per function_id)
    lines.push("# HELP edge_runtime_requests_total Total requests by function");
    lines.push("# TYPE edge_runtime_requests_total counter");
    for (const [fnId, statusMap] of requestCounts) {
      for (const [status, count] of statusMap) {
        lines.push(
          `edge_runtime_requests_total{function_id="${fnId}",status="${status}"} ${count}`,
        );
      }
    }

    // Histogram: request duration
    const buckets = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
    lines.push(
      "# HELP edge_runtime_request_duration_seconds Request duration histogram",
    );
    lines.push("# TYPE edge_runtime_request_duration_seconds histogram");
    for (const le of buckets) {
      const count = requestDurations.filter((d) => d <= le).length;
      lines.push(
        `edge_runtime_request_duration_seconds_bucket{le="${le}"} ${count}`,
      );
    }
    lines.push(
      `edge_runtime_request_duration_seconds_bucket{le="+Inf"} ${requestDurations.length}`,
    );
    lines.push(
      `edge_runtime_request_duration_seconds_sum ${requestDurations.reduce((a, b) => a + b, 0)}`,
    );
    lines.push(
      `edge_runtime_request_duration_seconds_count ${requestDurations.length}`,
    );

    // Gauge: memory bytes (from memStats)
    lines.push("# HELP edge_runtime_memory_bytes Worker memory usage");
    lines.push("# TYPE edge_runtime_memory_bytes gauge");
    try {
      const stats = await EdgeRuntime.userWorkers.memStats();
      for (const [servicePath, stat] of stats) {
        lines.push(
          `edge_runtime_memory_bytes{function_id="${servicePath}"} ${stat.usedHeapSize}`,
        );
      }
    } catch (_) {
      /* no workers */
    }

    // Counter: cold starts
    lines.push("# HELP edge_runtime_cold_starts_total Total cold starts");
    lines.push("# TYPE edge_runtime_cold_starts_total counter");
    lines.push(`edge_runtime_cold_starts_total ${coldStartsTotal}`);

    return new Response(lines.join("\n") + "\n", {
      headers: { "Content-Type": "text/plain; version=0.0.4" },
    });
  }

  // ─── Function Routing ───

  const fnId = req.headers.get("x-function-id");
  if (!fnId) {
    return Response.json(
      { error: "missing x-function-id header" },
      { status: 400 },
    );
  }

  const entry = functions.get(fnId);
  if (!entry) {
    return Response.json(
      { error: "function not found" },
      { status: 404 },
    );
  }

  // Warm restart: if eszip is loaded but worker was released (idle cleanup),
  // recreate the worker on demand.
  if (!entry.ready || !entry.worker) {
    try {
      const start = performance.now();
      entry.worker = await createWorkerForFunction(entry);
      entry.ready = true;
      const warmStartMs = Math.round(performance.now() - start);
      console.log(
        `function ${fnId} warm restarted (${warmStartMs}ms)`,
      );
    } catch (e) {
      console.error(`function ${fnId} failed to warm restart:`, e);
      return Response.json(
        { error: "function not ready", detail: e.message },
        { status: 503 },
      );
    }
  }

  entry.lastRequest = Date.now();

  const reqStart = performance.now();
  let resp: Response;

  try {
    const controller = new AbortController();
    resp = await entry.worker.fetch(req, { signal: controller.signal });
  } catch (e) {
    console.error(`function ${fnId} request error:`, e);

    if (e instanceof Deno.errors.WorkerAlreadyRetired) {
      // Worker was retired, try recreating
      try {
        entry.worker = await createWorkerForFunction(entry);
        entry.ready = true;
        resp = await entry.worker.fetch(req, {
          signal: new AbortController().signal,
        });
      } catch (retryErr) {
        entry.worker = null;
        entry.ready = false;
        resp = Response.json(
          { error: "function worker retired and restart failed" },
          { status: 503 },
        );
      }
    } else if (e instanceof Deno.errors.WorkerRequestCancelled) {
      resp = new Response(
        JSON.stringify({ error: "request cancelled (resource limit)" }),
        {
          status: 503,
          headers: {
            "Content-Type": "application/json",
            "Connection": "close",
          },
        },
      );
    } else {
      resp = Response.json(
        { error: e.message },
        { status: 500 },
      );
    }
  }

  // Record metrics
  const durationSec = (performance.now() - reqStart) / 1000;
  requestDurations.push(durationSec);

  if (!requestCounts.has(fnId)) {
    requestCounts.set(fnId, new Map());
  }
  const statusMap = requestCounts.get(fnId)!;
  statusMap.set(resp!.status, (statusMap.get(resp!.status) ?? 0) + 1);

  return resp!;
});
