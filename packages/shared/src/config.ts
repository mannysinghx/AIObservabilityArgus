/** Centralized env config with sane local defaults (matches .env.example). */
export const config = {
  clickhouseUrl: process.env.CLICKHOUSE_HTTP_URL ?? "http://localhost:8123",
  clickhouseDb: process.env.CLICKHOUSE_DB ?? "argus",
  clickhouseUser: process.env.CLICKHOUSE_USER ?? "argus",
  clickhousePassword: process.env.CLICKHOUSE_PASSWORD ?? "argus",

  redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",

  databaseUrl:
    process.env.DATABASE_URL ?? "postgres://argus:argus@localhost:5432/argus",

  detectionUrl: process.env.DETECTION_URL ?? "http://localhost:8000",
  detectionEnableL2: (process.env.DETECTION_ENABLE_L2 ?? "false") === "true",

  ingestPort: Number(process.env.INGEST_PORT ?? 3001),

  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL ?? "",
  alertMinSeverity: (process.env.ALERT_MIN_SEVERITY ?? "high") as
    | "info"
    | "low"
    | "medium"
    | "high"
    | "critical",
};

export const STREAM_KEY = "argus:ingest";
export const GROUP_TRACE = "trace-workers";
export const GROUP_SECURITY = "security-workers";

export const SEVERITY_ORDER: Record<string, number> = {
  none: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};
