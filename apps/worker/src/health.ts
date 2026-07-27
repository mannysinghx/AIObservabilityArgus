/**
 * A tiny HTTP surface on the worker.
 *
 * The worker had none at all, which meant the component most likely to fail
 * quietly was the one nothing could ask about. A stalled consumer group looks
 * identical from outside to an idle one: the process is up, the container is
 * healthy, and spans have simply stopped being written. `/health` here reports
 * whether the consumers are actually advancing, not merely whether the process
 * exists.
 *
 * node:http rather than Fastify: this serves two routes and should not be able
 * to fail in ways the worker has to reason about.
 */
import { createServer, type Server } from "node:http";
import { metrics, refreshQueueMetrics } from "@argus/shared";

const PORT = Number(process.env.WORKER_HEALTH_PORT ?? process.env.PORT ?? 3003);

/**
 * Pending entries above which a group is considered stalled rather than busy.
 * A backlog is normal under load; a backlog that persists while nothing is
 * being acked is not, and pending is the number that distinguishes them.
 */
const STALL_PENDING = Number(process.env.WORKER_STALL_PENDING ?? 10_000);

export function startHealthServer(): Server {
  const server = createServer((req, res) => {
    const path = (req.url ?? "/").split("?")[0];

    if (path === "/metrics") {
      refreshQueueMetrics()
        .catch(() => {})
        .finally(() => {
          res.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
          res.end(metrics.render());
        });
      return;
    }

    if (path === "/health") {
      refreshQueueMetrics()
        .then((stats) => {
          const stalled = stats.groups.filter((g) => g.pending > STALL_PENDING);
          // 503 when a group is backed up, so a platform health check restarts
          // or pages rather than reporting green over a stopped pipeline.
          const ok = stalled.length === 0;
          res.writeHead(ok ? 200 : 503, { "content-type": "application/json" });
          res.end(JSON.stringify({
            status: ok ? "ok" : "degraded",
            service: "argus-worker",
            streamLength: stats.streamLength,
            dlqLength: stats.dlqLength,
            groups: stats.groups,
            stalled: stalled.map((g) => g.group),
          }));
        })
        .catch((err) => {
          // Redis unreachable is itself degraded — the worker cannot consume.
          res.writeHead(503, { "content-type": "application/json" });
          res.end(JSON.stringify({ status: "degraded", service: "argus-worker", error: String(err) }));
        });
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end('{"error":"not found"}');
  });

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[worker] health + metrics on :${PORT}`);
  });
  server.on("error", (err) => {
    // A port clash must not take down the consumers — telemetry processing is
    // the job, this is the window onto it.
    console.error("[worker] health server failed to bind:", err);
  });
  return server;
}
