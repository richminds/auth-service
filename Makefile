.PHONY: install install-dev dev run test test-cov lint fmt docker docker-up docker-down

PY ?= python

install:
	$(PY) -m pip install -r requirements.txt

install-dev:
	$(PY) -m pip install -r requirements-dev.txt

# Reload loop on AUTHSVC_PORT (default 8100). Swagger: http://localhost:8100/docs
dev:
	$(PY) -m uvicorn app.main:app --reload --port $${AUTHSVC_PORT:-8100}

run:
	$(PY) run.py

test:
	$(PY) -m pytest -q

test-cov:
	$(PY) -m pytest --cov=app --cov=features --cov=sdk --cov-report=term-missing

lint:
	$(PY) -m ruff check app features sdk tests

fmt:
	$(PY) -m ruff check --fix app features sdk tests

docker:
	docker build -t auth-service:latest .

docker-up:
	docker compose up --build

docker-down:
	docker compose down
