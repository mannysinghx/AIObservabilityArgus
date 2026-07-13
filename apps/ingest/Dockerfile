# Argus ingestion API. Build context = repo root (needs the npm workspace).
#   docker build -f apps/ingest/Dockerfile -t argus-ingest .
FROM node:20-slim

WORKDIR /app

# Install workspace deps. Copy manifests first for better layer caching.
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/ingest/package.json apps/ingest/
COPY apps/worker/package.json apps/worker/
RUN npm install --no-audit --no-fund

# App source (tsx runs TypeScript directly — no build step).
COPY tsconfig.base.json tsconfig.json ./
COPY packages ./packages
COPY apps ./apps
COPY scripts ./scripts
COPY deploy ./deploy

ENV NODE_ENV=production
EXPOSE 3001

# Apply migrations (idempotent) before serving, so a fresh deploy self-heals its
# schema. Binds $PORT (Railway/Render) or falls back to 3001.
CMD ["sh", "-c", "node scripts/migrate.mjs && npx tsx apps/ingest/src/server.ts"]
