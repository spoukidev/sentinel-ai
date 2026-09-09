.PHONY: setup dev seed test lint format reset-demo
setup:
	python scripts/setup-env.py
dev:
	docker compose up --build
seed:
	docker compose exec api python -m app.seed
test:
	docker compose exec api pytest -q
	cd apps/web && npm run test:e2e
lint:
	docker compose exec api ruff check .
	cd apps/web && npm run lint && npm run typecheck
format:
	docker compose exec api ruff format .
	cd apps/web && npm run format
reset-demo:
	@echo "Destructive reset is intentionally manual: docker compose down -v; docker compose up --build. This deletes all workspace data."
