import pg from "pg";
import { createHash } from "node:crypto";
import { config } from "@argus/shared";

// One shared Postgres pool for the dashboard service (onboarding + auth).
export const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 6 });

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}
