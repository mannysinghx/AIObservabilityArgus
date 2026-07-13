import { GROUP_TRACE, GROUP_SECURITY } from "@argus/shared";
import { runConsumer } from "./consumer.js";
import { handleTraceBatch } from "./traceWorker.js";
import { handleSecurityBatch } from "./securityWorker.js";

/**
 * Entry point runs both consumer groups in one process for local/dev. In
 * production they scale independently — split into two deployments, same code.
 */
const consumer = process.env.HOSTNAME ?? `w-${process.pid}`;

async function main() {
  console.log("argus-worker starting (trace + security consumers)");
  await Promise.all([
    runConsumer(GROUP_TRACE, consumer, handleTraceBatch),
    runConsumer(GROUP_SECURITY, consumer, handleSecurityBatch),
  ]);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
