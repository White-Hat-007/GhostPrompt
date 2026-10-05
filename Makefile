.PHONY: help dev backend frontend test lint docker-up docker-down migrate seed clean

# Colors
CYAN := \033[36m
GREEN := \033[32m
RESET := \033[0m

help: ## Show this help
	@echo "$(CYAN)GhostPrompt$(RESET) — AI Runtime Security Platform"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'

# Development
dev: ## Start full dev environment
	docker-compose up -d postgres redis
	@echo "Starting backend..."
	cd backend && uvicorn app.main:app --reload --port 8000 &
	@echo "Starting frontend..."
	cd frontend && npm run dev &
	@echo "$(GREEN)GhostPrompt is running!$(RESET)"
	@echo "  Dashboard: http://localhost:3000"
	@echo "  API:       http://localhost:8000"
	@echo "  Docs:      http://localhost:8000/docs"

backend: ## Start backend only
	cd backend && uvicorn app.main:app --reload --port 8000

frontend: ## Start frontend only
	cd frontend && npm run dev

# Testing
test: ## Run all tests
	cd backend && pytest tests/ -v --cov=app --cov-report=term-missing
	cd frontend && npm run lint

test-backend: ## Run backend tests only
	cd backend && pytest tests/ -v --cov=app

test-firewall: ## Run firewall engine tests
	cd backend && pytest tests/test_firewall.py -v

lint: ## Run linting
	cd backend && ruff check .
	cd frontend && npm run lint

# Docker
docker-up: ## Start full Docker stack
	docker-compose up -d
	@echo "$(GREEN)All services started$(RESET)"

docker-down: ## Stop all services
	docker-compose down

docker-build: ## Build all Docker images
	docker-compose build

docker-logs: ## View logs
	docker-compose logs -f

# Database
migrate: ## Run database migrations
	cd backend && alembic upgrade head

migrate-create: ## Create a new migration
	cd backend && alembic revision --autogenerate -m "$(msg)"

migrate-down: ## Rollback last migration
	cd backend && alembic downgrade -1

# Setup
install: ## Install all dependencies
	cd backend && pip install -r requirements.txt
	cd frontend && npm install

setup: install docker-up migrate ## Full setup: install deps, start infra, run migrations
	@echo "$(GREEN)GhostPrompt setup complete!$(RESET)"

# Production
build: ## Build production images
	docker build -t ghostprompt-backend:latest ./backend
	docker build -t ghostprompt-frontend:latest ./frontend

# Cleanup
clean: ## Clean temporary files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	cd frontend && rm -rf .next node_modules/.cache 2>/dev/null || true
	@echo "$(GREEN)Cleaned!$(RESET)"
