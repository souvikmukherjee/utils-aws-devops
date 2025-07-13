# Makefile for Agentic Infrastructure Manager

.PHONY: help install install-dev test lint format type-check security clean docs docker build run

# Default target
help:
	@echo "Available targets:"
	@echo "  install       Install package and dependencies"
	@echo "  install-dev   Install package with development dependencies"
	@echo "  test          Run tests"
	@echo "  lint          Run linting checks"
	@echo "  format        Format code with black"
	@echo "  type-check    Run type checking with mypy"
	@echo "  security      Run security checks"
	@echo "  clean         Clean up build artifacts"
	@echo "  docs          Generate documentation"
	@echo "  docker        Build Docker image"
	@echo "  build         Build package"
	@echo "  run           Run the agent CLI"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"
	pip install -r requirements.txt

# Testing
test:
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-security:
	pytest tests/security/ -v

# Code quality
lint:
	flake8 src tests
	black --check src tests
	mypy src

format:
	black src tests
	isort src tests

type-check:
	mypy src

# Security
security:
	bandit -r src
	safety check
	checkov --directory . --framework terraform

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

# Documentation
docs:
	cd docs && make html

docs-serve:
	cd docs/_build/html && python -m http.server 8000

# Docker
docker:
	docker build -t agentic-infra-manager .

docker-run:
	docker run -it --rm agentic-infra-manager

# Package building
build:
	python -m build

# Development server
run:
	python -m agentic_infra_manager.cli

# Quick start for development
dev-setup: install-dev
	@echo "Setting up development environment..."
	mkdir -p config logs workspace
	@echo "Development environment ready!"
	@echo "Next steps:"
	@echo "1. Copy config/agent.yaml.example to config/agent.yaml"
	@echo "2. Set your API keys and configuration"
	@echo "3. Run: make run -- --help"

# Example commands
example-init:
	python -m agentic_infra_manager.cli init --config config/agent.yaml

example-analyze:
	python -m agentic_infra_manager.cli analyze https://github.com/tiangolo/fastapi --output results.json

example-config:
	python -m agentic_infra_manager.cli config

# Environment checks
check-env:
	@echo "Checking environment..."
	@python -c "import sys; print(f'Python: {sys.version}')"
	@python -c "import boto3; print(f'boto3: {boto3.__version__}')" 2>/dev/null || echo "boto3: Not installed"
	@python -c "import kubernetes; print(f'kubernetes: {kubernetes.__version__}')" 2>/dev/null || echo "kubernetes: Not installed"
	@echo "AWS CLI:" && aws --version 2>/dev/null || echo "AWS CLI: Not installed"
	@echo "kubectl:" && kubectl version --client 2>/dev/null || echo "kubectl: Not installed"
	@echo "terraform:" && terraform version 2>/dev/null || echo "terraform: Not installed"

# AWS setup helpers
aws-configure:
	aws configure

aws-test:
	aws sts get-caller-identity

# GitHub setup
github-setup:
	@echo "To set up GitHub integration:"
	@echo "1. Create a personal access token at https://github.com/settings/tokens"
	@echo "2. Set the token: export GITHUB_TOKEN=your_token_here"
	@echo "3. Or add it to your config/agent.yaml file"

# Quick test of the agent
quick-test:
	python -c "from src.agentic_infra_manager import InfrastructureAgent; print('Agent import successful')"

# Deployment helpers
deploy-dev:
	@echo "This would deploy to development environment"
	@echo "Implementation depends on your specific infrastructure"

deploy-staging:
	@echo "This would deploy to staging environment"
	@echo "Implementation depends on your specific infrastructure"

deploy-prod:
	@echo "This would deploy to production environment"
	@echo "Implementation depends on your specific infrastructure" 