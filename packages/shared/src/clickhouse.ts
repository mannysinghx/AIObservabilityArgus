import { createClient, type ClickHouseClient } from "@clickhouse/client";
import { config } from "./config.js";

let client: ClickHouseClient | null = null;

export function ch(): ClickHouseClient {
  if (!client) {
    client = createClient({
      url: config.clickhouseUrl,
      username: config.clickhouseUser,
      password: config.clickhousePassword,
      database: config.clickhouseDb,
      clickhouse_settings: {
        async_insert: 1,
        wait_for_async_insert: 1,
      },
    });
  }
  return client;
}

/** ClickHouse DateTime64(3) wants 'YYYY-MM-DD HH:MM:SS.mmm' in UTC. */
export function toChDateTime(iso: string): string {
  const d = new Date(iso);
  return d.toISOString().replace("T", " ").replace("Z", "");
}

export async function insertRows(table: string, rows: Record<string, unknown>[]) {
  if (rows.length === 0) return;
  await ch().insert({ table, values: rows, format: "JSONEachRow" });
}
