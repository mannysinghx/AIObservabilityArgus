/**
 * Dashboard entrypoint. All routing lives in app.ts; this file only owns the
 * decision to bind a port, which is exactly the part a test must not do.
 */
import { config } from "@argus/shared";
import { buildApp } from "./app.js";

const port = Number(process.env.PORT ?? process.env.WEB_PORT ?? 3002);

const app = await buildApp();
try {
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`argus-web on :${port} (clickhouse: ${config.clickhouseUrl})`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
