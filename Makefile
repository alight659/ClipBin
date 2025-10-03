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
	@echo "  install-dev     Install development dependencies (including linting tools)"
	@echo "  setup          Set up project directories and install dependencies"
	@echo "  test           Run all tests"
	@echo "  test-coverage  Run tests with coverage report"
	@echo "  test-fast      Run tests with minimal output"
	@echo "  dev            Run development server"
	@echo "  run            Alias for dev command"
	@echo "  lint           Check code style with flake8"
	@echo "  lint-check     Check code formatting and linting (no changes applied)"
	@echo "  lint-fix       Apply code formatting and linting fixes"
	@echo "  black-check    Check code formatting with Black (no changes applied)"
	@echo "  black-format   Format code using Black"
	@echo "  format         Alias for black-format"
	@echo "  clean          Remove cache and build files"
	@echo "  db-reset       Delete the database file"

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements.txt
	$(PIP) install black flake8

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
	flake8 *.py --max-line-length=120 --ignore=E203,W503

lint-check:
	@echo "Running code formatting and linting checks..."
	@echo "Checking with Black formatter..."
	black --check --diff --line-length=120 *.py
	@echo "Checking with Flake8 linter..."
	flake8 *.py --max-line-length=120 --ignore=E203,W503
	@echo "✅ All linting checks passed!"

lint-fix: black-format
	@echo "Applied code formatting fixes."

black-check:
	black --check --diff --line-length=120 *.py

black-format:
	black *.py --line-length=120

format: black-format

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
