# Argus trace + security workers. Build context = repo root.
#   docker build -f apps/worker/Dockerfile -t argus-worker .
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/ingest/package.json apps/ingest/
COPY apps/worker/package.json apps/worker/
RUN npm install --no-audit --no-fund

COPY tsconfig.base.json tsconfig.json ./
COPY packages ./packages
COPY apps ./apps
COPY scripts ./scripts
COPY deploy ./deploy

ENV NODE_ENV=production

# The worker doesn't serve HTTP; it consumes the Redis stream. Migrations are
# run by the ingest service — the worker just retries inserts until tables exist.
CMD ["npx", "tsx", "apps/worker/src/index.ts"]
