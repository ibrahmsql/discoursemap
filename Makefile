# DiscourseMap v2.1 Makefile

.PHONY: help install test demo clean lint format docker-build docker-run docs

# Default target
help:
	@echo "DiscourseMap v2.1 - Available commands:"
	@echo ""
	@echo "  install     - Install DiscourseMap and dependencies"
	@echo "  test        - Run unit tests"
	@echo "  demo        - Run demo script"
	@echo "  lint        - Run code linting"
	@echo "  format      - Format code with black"
	@echo "  clean       - Clean build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run  - Run Docker container"
	@echo "  docs        - Generate documentation"
	@echo "  package     - Build distribution packages"
	@echo "  upload      - Upload to PyPI (requires credentials)"
	@echo ""

# Installation
install:
	@echo "Installing DiscourseMap v2.1..."
	pip install -r requirements.txt
	pip install -e .
	@echo "✓ Installation completed"

install-dev:
	@echo "Installing development dependencies..."
	pip install -r requirements.txt
	pip install -e .[dev,advanced,reporting,integrations]
	@echo "✓ Development installation completed"

# Testing
test:
	@echo "Running unit tests..."
	python -m pytest tests/ -v --cov=discoursemap --cov-report=term-missing
	@echo "✓ Tests completed"

test-import:
	@echo "Testing import..."
	python -c "import discoursemap; print('✓ Import successful')"

# Demo
demo:
	@echo "Running DiscourseMap demo..."
	python demo.py

# Code quality
lint:
	@echo "Running linting..."
	flake8 discoursemap --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 discoursemap --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
	@echo "✓ Linting completed"

format:
	@echo "Formatting code..."
	black discoursemap tests demo.py
	@echo "✓ Code formatted"

format-check:
	@echo "Checking code format..."
	black --check discoursemap tests demo.py

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "✓ Cleanup completed"

# Docker
docker-build:
	@echo "Building Docker image..."
	docker build -t discoursemap:2.1.0 .
	docker tag discoursemap:2.1.0 discoursemap:latest
	@echo "✓ Docker image built"

docker-run:
	@echo "Running Docker container..."
	docker run --rm -it discoursemap:latest

docker-compose-up:
	@echo "Starting Docker Compose services..."
	docker-compose up -d

docker-compose-down:
	@echo "Stopping Docker Compose services..."
	docker-compose down

# Documentation
docs:
	@echo "Generating documentation..."
	@echo "📖 See MODULAR_ARCHITECTURE.md for detailed documentation"
	@echo "✓ Documentation available"

# Packaging
package:
	@echo "Building distribution packages..."
	python -m build
	@echo "✓ Packages built in dist/"

upload-test:
	@echo "Uploading to Test PyPI..."
	python -m twine upload --repository testpypi dist/*

upload:
	@echo "Uploading to PyPI..."
	python -m twine upload dist/*

# Security
security-check:
	@echo "Running security checks..."
	safety check
	bandit -r discoursemap
	@echo "✓ Security checks completed"

# Performance
benchmark:
	@echo "Running performance benchmarks..."
	@python -c "\
import time; \
import discoursemap; \
print('🚀 DiscourseMap Performance Benchmark'); \
print('=' * 40); \
start_time = time.time(); \
from discoursemap.core import DiscourseScanner; \
from discoursemap.monitoring import HealthChecker; \
from discoursemap.reporting import JSONReporter; \
end_time = time.time(); \
print(f'Module import time: {end_time - start_time:.3f}s'); \
print('✓ Benchmark completed')"

# Development helpers
dev-setup: install-dev
	@echo "Setting up development environment..."
	pre-commit install || echo "pre-commit not available"
	@echo "✓ Development environment ready"

check-all: format-check lint test security-check
	@echo "✓ All checks passed"

# Release helpers
version:
	@python -c "import discoursemap; print(f'DiscourseMap v{discoursemap.__version__}')"

release-check: clean check-all package
	@echo "✓ Release checks completed"

# Quick commands
quick-test: test-import demo
	@echo "✓ Quick test completed"

all: clean install test demo
	@echo "✓ Full build and test completed"