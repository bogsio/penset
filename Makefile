.PHONY: help install install-dev run migrate makemigrations test lint format clean

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install production dependencies
	uv sync

install-dev: ## Install development dependencies
	uv sync --extra dev

run: ## Run the Django development server
	uv run python manage.py runserver

migrate: ## Run database migrations
	uv run python manage.py migrate

makemigrations: ## Create database migrations
	uv run python manage.py makemigrations

test: ## Run tests
	uv run pytest

lint: ## Run linting
	uv run flake8 .
	uv run isort --check-only .

format: ## Format code
	uv run black .
	uv run isort .


clean: ## Clean up temporary files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf build
	rm -rf dist

setup: install-dev migrate ## Complete setup for development
	@echo "Setup complete! Run 'make run' to start the development server."

create-superuser: ## Create a superuser
	uv run python manage.py create_superuser

shell: ## Open Django shell
	uv run python manage.py shell

collectstatic: ## Collect static files
	uv run python manage.py collectstatic --noinput
