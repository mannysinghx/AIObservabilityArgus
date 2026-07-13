#!/usr/bin/env node
/**
 * Idempotent, cross-platform migration runner (VMs, Railway, anywhere).
 *
 * Applies every SQL file in deploy/clickhouse/migrations and
 * deploy/postgres/migrations. All statements use IF NOT EXISTS, so re-running is
 * safe — this runs on every deploy/boot, not just first init. Waits for both
 * databases to be reachable before applying.
 *
 * Config (env, with local defaults):
 *   CLICKHOUSE_HTTP_URL  CLICKHOUSE_USER  CLICKHOUSE_PASSWORD  CLICKHOUSE_DB
 *   DATABASE_URL         (postgres)
 */
import pg from "pg";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const CH_URL = process.env.CLICKHOUSE_HTTP_URL ?? "http://localhost:8123";
const CH_USER = process.env.CLICKHOUSE_USER ?? "argus";
const CH_PASS = process.env.CLICKHOUSE_PASSWORD ?? "argus";
const CH_DB = process.env.CLICKHOUSE_DB ?? "argus";
const PG_URL = process.env.DATABASE_URL ?? "postgres://argus:argus@localhost:5432/argus";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function migrationsIn(rel) {
  const dir = join(ROOT, rel);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => ({ name: f, sql: readFileSync(join(dir, f), "utf8") }));
}

// ---- ClickHouse over HTTP ----
async function chExec(sql, { withDb = true } = {}) {
  const u = new URL(CH_URL);
  u.searchParams.set("user", CH_USER);
  u.searchParams.set("password", CH_PASS);
  if (withDb) u.searchParams.set("database", CH_DB);
  const res = await fetch(u, { method: "POST", body: sql });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`ClickHouse: ${res.status} ${body.slice(0, 300)}\n  stmt: ${sql.slice(0, 120)}`);
  }
}

async function waitForClickHouse() {
  const ping = new URL(CH_URL);
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(new URL("/ping", ping));
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await sleep(2000);
  }
  throw new Error(`ClickHouse not reachable at ${CH_URL}`);
}

function splitStatements(sql) {
  // Strip line comments FIRST (a comment may contain a ';'), then split. Our
  // migrations never use '--' inside string literals, so this is safe here.
  const noComments = sql
    .split("\n")
    .map((l) => {
      const i = l.indexOf("--");
      return i >= 0 ? l.slice(0, i) : l;
    })
    .join("\n");
  return noComments
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    // USE / CREATE DATABASE are handled explicitly against the HTTP database param.
    .filter((s) => !/^use\b/i.test(s) && !/^create\s+database/i.test(s));
}

async function migrateClickHouse() {
  await waitForClickHouse();
  await chExec(`CREATE DATABASE IF NOT EXISTS ${CH_DB}`, { withDb: false });
  for (const { name, sql } of migrationsIn("deploy/clickhouse/migrations")) {
    for (const stmt of splitStatements(sql)) {
      await chExec(stmt);
    }
    console.log(`  clickhouse ✓ ${name}`);
  }
}

// ---- Postgres ----
async function migratePostgres() {
  const client = new pg.Client({ connectionString: PG_URL });
  for (let i = 0; i < 60; i++) {
    try {
      await client.connect();
      break;
    } catch {
      if (i === 59) throw new Error(`Postgres not reachable at ${PG_URL}`);
      await sleep(2000);
    }
  }
  try {
    for (const { name, sql } of migrationsIn("deploy/postgres/migrations")) {
      // pg runs multi-statement strings in one simple query; comments are fine.
      await client.query(sql);
      console.log(`  postgres   ✓ ${name}`);
    }
  } finally {
    await client.end();
  }
}

async function main() {
  console.log("Running migrations…");
  await migrateClickHouse();
  await migratePostgres();
  console.log("Migrations complete.");
}

main().catch((err) => {
  console.error("Migration failed:", err.message);
  process.exit(1);
});
