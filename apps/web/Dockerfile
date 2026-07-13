# Argus web dashboard. Build context = repo root (npm workspace).
#   docker build -f apps/web/Dockerfile -t argus-web .
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY apps/ingest/package.json apps/ingest/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
RUN npm install --no-audit --no-fund

COPY tsconfig.base.json tsconfig.json ./
COPY packages ./packages
COPY apps ./apps

ENV NODE_ENV=production
EXPOSE 3002

# Public service; binds 0.0.0.0 (Railway edge + health check reach it over IPv4).
CMD ["npx", "tsx", "apps/web/src/server.ts"]
