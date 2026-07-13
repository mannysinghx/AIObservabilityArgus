.PHONY: help up down logs ps reset detection-install detection-test detection-run ingest-install ingest-run demo

COMPOSE := docker compose -f deploy/docker-compose.yml

help:
	@echo "Argus — Phase 1 (Security Sidecar)"
	@echo ""
	@echo "  make up                start infra (clickhouse, postgres, redis, minio)"
	@echo "  make down              stop infra"
	@echo "  make reset             stop infra and wipe volumes"
	@echo "  make logs              tail infra logs"
	@echo "  make ps                show container status"
	@echo ""
	@echo "  make detection-install pip install the detection service (editable)"
	@echo "  make detection-test    run detection unit tests + quality gate"
	@echo "  make detection-run     run the detection FastAPI service (:8000)"
	@echo ""
	@echo "  make ingest-install    npm install ingestion API + workers"
	@echo "  make ingest-run        run ingestion API + workers (:3001)"
	@echo ""
	@echo "  make demo              send the poisoned-document demo trace"

up:
	$(COMPOSE) up -d
	@echo "waiting for clickhouse to be healthy..."
	@until [ "$$(docker inspect -f '{{.State.Health.Status}}' argus-clickhouse 2>/dev/null)" = "healthy" ]; do sleep 1; done
	@echo "infra up. clickhouse http :8123 · postgres :5432 · redis :6379 · minio :9002 (console :9001)"

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

detection-install:
	cd services/detection && python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

detection-test:
	cd services/detection && . .venv/bin/activate && pytest -q

detection-run:
	cd services/detection && . .venv/bin/activate && uvicorn argus_detection.app:app --port 8000 --reload

ingest-install:
	cd apps/ingest && npm install

ingest-run:
	cd apps/ingest && npm run dev

demo:
	cd demo && python3 send_poisoned_trace.py
