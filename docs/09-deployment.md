# 09 — Deployment

Argus is self-hostable by anyone. Three supported paths, from simplest to most
managed:

- **A. VM with Docker Compose** — one command, the whole platform. ✅ verified
- **B. Railway** — managed Postgres/Redis + deployed services from this repo
- **C. Bare / Kubernetes** — run the images anywhere; point them at your stores

All services are configured entirely by environment variables (see
[`packages/shared/src/config.ts`](../packages/shared/src/config.ts) and the
detection service's env), so the same images run in every environment.

## Data durability

Argus stores **everything, untruncated**, for future analysis:

- `observations.input_full` / `output_full` — complete prompt/completion/tool
  I/O (a 4 000-char preview is kept separately only for fast list rendering).
- `raw_events` — an append-only archive of every ingested envelope, so historical
  traffic can be **re-scored by future detector versions** (L2/L3/L4 upgrades)
  and replayed for forensics.
- `security_events` — every finding with full layer provenance.

None of these have a default TTL — nothing is deleted unless you configure
per-project retention. On ClickHouse this compresses extremely well (ZSTD).

---

## A. VM with Docker Compose (recommended for self-host)

Requirements: a Linux VM with Docker + Docker Compose. 2 vCPU / 4 GB RAM is
enough to start.

```bash
git clone https://github.com/mannysinghx/AIObservabilityArgus.git
cd AIObservabilityArgus
cp .env.example .env          # then edit secrets (see below)

docker compose -f deploy/docker-compose.prod.yml up -d --build
```

This builds the three service images, starts ClickHouse/Postgres/Redis/MinIO,
runs migrations once (idempotent), and starts detection + ingest + workers. The
only published host port is the ingestion API (`3001`).

**Before exposing publicly, change these in `.env`:**

```
CLICKHOUSE_PASSWORD=<strong>
POSTGRES_PASSWORD=<strong>
MINIO_ROOT_PASSWORD=<strong>
```

…and rotate the seeded dev API key (`pk-dev` / `sk-dev` in
`deploy/postgres/migrations/001_init.sql`) — issue a real project key and delete
the dev row. Put a TLS-terminating reverse proxy (Caddy, nginx, Traefik) in
front of the ingest port; don't expose ClickHouse/Postgres to the internet.

Verify:

```bash
curl -s localhost:3001/health
docker compose -f deploy/docker-compose.prod.yml ps
```

Update to a new version: `git pull && docker compose -f deploy/docker-compose.prod.yml up -d --build`
(migrations re-apply idempotently on the ingest container's boot).

---

## B. Railway

Railway hosts the stateful stores and the services. Topology:

| Railway service | Source | Provides |
|---|---|---|
| **Postgres** | Railway plugin (Add → Database → PostgreSQL) | `DATABASE_URL` |
| **Redis** | Railway plugin (Add → Database → Redis) | `REDIS_URL` |
| **ClickHouse** | Deploy from Docker image `clickhouse/clickhouse-server:24.8` + a volume on `/var/lib/clickhouse` | trace/event store |
| **detection** | This repo, `services/detection/railway.json` | detection API |
| **ingest** | This repo, `apps/ingest/railway.json` (public) | ingestion API |
| **worker** | This repo, `apps/worker/railway.json` | consumers |

MinIO is **optional** in Phase 1 (full content lives in ClickHouse) — skip it
unless you enable blob offload later.

### Steps

1. **Create a project** and add the **PostgreSQL** and **Redis** plugins.
2. **Add ClickHouse**: *New → Docker Image →* `clickhouse/clickhouse-server:24.8`.
   Attach a volume at `/var/lib/clickhouse`. Set service variables:
   `CLICKHOUSE_USER=argus`, `CLICKHOUSE_PASSWORD=<strong>`, `CLICKHOUSE_DB=argus`,
   `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1`. Note its private hostname
   (e.g. `clickhouse.railway.internal`, HTTP port `8123`).
3. **Deploy the three repo services**: *New → GitHub Repo →* this repo, three
   times. For each, set **Config-as-code path** to the service's `railway.json`
   (`apps/ingest/railway.json`, `apps/worker/railway.json`,
   `services/detection/railway.json`). Keep the **root directory as the repo
   root** — the Dockerfiles need the whole workspace as build context.
4. **Set environment variables** (use Railway *reference variables* to point at
   the plugin values):

   Shared by **ingest** and **worker**:
   ```
   DATABASE_URL         = ${{Postgres.DATABASE_URL}}
   REDIS_URL            = ${{Redis.REDIS_URL}}
   CLICKHOUSE_HTTP_URL  = http://clickhouse.railway.internal:8123
   CLICKHOUSE_USER      = argus
   CLICKHOUSE_PASSWORD  = <same as ClickHouse service>
   CLICKHOUSE_DB        = argus
   DETECTION_URL        = http://detection.railway.internal:8000
   ALERT_MIN_SEVERITY   = high
   ```
   **detection** only needs:
   ```
   PORT = 8000
   ```
   (Set a fixed `PORT=8000` on detection so `DETECTION_URL` above is stable over
   Railway's private network.)
5. **Expose ingest publicly**: on the ingest service, *Settings → Networking →
   Generate Domain*. Point your SDKs at `https://<ingest-domain>`.
6. **Migrations run automatically** on the ingest service's first boot
   (`node scripts/migrate.mjs` in its Dockerfile CMD) — no manual step.

### Notes

- Deploy order doesn't matter: the worker retries inserts until the ingest
  service has run migrations; the consumer loop is idempotent.
- Scale `worker` replicas up for throughput (independent Redis consumer group);
  keep `ingest` behind Railway's load balancer.
- To enable the L2 classifier ensemble, rebuild detection with the `l2` extra
  and set `DETECTION_ENABLE_L2=true` (needs more memory — size accordingly).

---

## C. Bare metal / Kubernetes

The images are plain containers with no host assumptions:

- `argus-ingest` and `argus-worker` — Node; env: `DATABASE_URL`, `REDIS_URL`,
  `CLICKHOUSE_HTTP_URL` (+ user/pass/db), `DETECTION_URL`. Ingest serves `$PORT`
  (or `INGEST_PORT`, default 3001) and runs migrations on boot.
- `argus-detection` — Python/uvicorn on `$PORT` (default 8000).

Point them at managed stores (ClickHouse Cloud, RDS/Neon, Upstash/ElastiCache,
S3). Run `node scripts/migrate.mjs` once against your ClickHouse + Postgres (or
let the ingest container do it). A Helm chart is on the roadmap
([docs/06](06-roadmap.md)); until then these three Deployments + the managed
stores are all you need.

## Environment variable reference

| Variable | Used by | Default | Notes |
|---|---|---|---|
| `CLICKHOUSE_HTTP_URL` | ingest, worker, migrate | `http://localhost:8123` | |
| `CLICKHOUSE_USER/PASSWORD/DB` | all | `argus`/`argus`/`argus` | change in prod |
| `DATABASE_URL` | ingest, migrate | `postgres://argus:argus@localhost:5432/argus` | |
| `REDIS_URL` | ingest, worker | `redis://localhost:6379` | |
| `DETECTION_URL` | worker | `http://localhost:8000` | |
| `DETECTION_ENABLE_L2` | worker→detection | `false` | opt-in classifier ensemble |
| `PORT` / `INGEST_PORT` | ingest, detection | `3001` / `8000` | platform-provided `PORT` wins |
| `ALERT_WEBHOOK_URL` | worker | _(empty)_ | logs alerts if unset |
| `ALERT_MIN_SEVERITY` | worker | `high` | `info`…`critical` |
