.PHONY: test lint format audit pre-push clean seed run install-hooks docker-build docker-up docker-down

test:
	uv run pytest tests/ -v --cov=app --cov-branch --cov-fail-under=80

lint:
	uv run ruff check .
	uv run mypy --strict .

format:
	uv run ruff format .

audit:
	uv run pip-audit

pre-push:
	bash scripts/pre_push_check.sh

seed:
	uv run python sample_data/seed_ecommerce.py

run:
	uv run python -m app.server

install-hooks:
	@echo "Installing Git pre-push hook..."
	@mkdir -p .git/hooks
	@cp scripts/pre_push_check.sh .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "✓ Pre-push hook installed"

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
