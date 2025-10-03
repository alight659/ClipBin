# ClipBin Makefile
.DEFAULT_GOAL := help
.PHONY: help install test clean lint format setup dev run

PYTHON := python
PIP := pip
PYTEST := python -m pytest
TEST_PATH := tests/

help: ## Show this help message
	@echo "ClipBin Makefile Commands:"
	@echo "========================="
	@echo ""
	@echo "Available commands:"
	@echo "  help            Show this help message"
	@echo "  install         Install required dependencies"
	@echo "  install-dev     Install development dependencies (including Black)"
	@echo "  setup           Set up project directories and install dependencies"
	@echo "  test            Run all tests"
	@echo "  test-coverage   Run tests with coverage report"
	@echo "  test-fast       Run tests with minimal output"
	@echo "  dev             Run development server"
	@echo "  run             Alias for dev command"
	@echo "  lint            Check code formatting with Black"
	@echo "  format          Format code using Black"
	@echo "  clean           Remove cache and build files"
	@echo "  db-reset        Delete the database file"

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements.txt
	$(PIP) install black

setup: install
	mkdir -p htmlcov
	mkdir -p .pytest_cache

test:
	$(PYTEST) tests/test_additional.py tests/test_sqlite.py tests/test_basic_app.py

test-coverage:
	$(PYTEST) tests/test_additional.py tests/test_sqlite.py tests/test_basic_app.py \
		--cov=. \
		--cov-report=html \
		--cov-report=term-missing

test-fast:
	$(PYTEST) tests/test_additional.py tests/test_sqlite.py tests/test_basic_app.py --tb=short

dev:
	$(PYTHON) app.py

run: dev

lint:
	find . -name "*.py" -not -path "./.venv/*" -not -path "./venv/*" | xargs black --check --line-length=120

format:
	find . -name "*.py" -not -path "./.venv/*" -not -path "./venv/*" | xargs black --line-length=120
	@echo "Applied code formatting with Black."


clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/

db-reset:
	rm -f clipbin.db
