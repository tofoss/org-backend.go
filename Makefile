# Makefile for org-go backend testing and development

.PHONY: test test-coverage test-verbose test-race test-integration clean lint fmt vet help

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Test targets
test: ## Run all tests
	go test ./...

test-verbose: ## Run tests with verbose output
	go test -v ./...

test-coverage: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-race: ## Run tests with race detector
	go test -race ./...

test-integration: ## Run integration tests only
	go test -v ./... -run TestIntegration

test-unit: ## Run unit tests only (exclude integration tests)
	go test -v ./... -run "^Test[^I].*" -short

test-ci: ## Run tests suitable for CI (coverage + race detection)
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Code quality targets
lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

# Development targets
build: ## Build the application
	go build -o bin/server cmd/server/main.go

run: ## Run the development server
	go run cmd/server/main.go

clean: ## Clean build artifacts and test files
	rm -f coverage.out coverage.html
	rm -rf bin/

# Database targets
test-db-setup: ## Set up test database (for integration tests)
	@echo "Setting up test database..."
	# Add your test database setup commands here

# Dependencies
deps: ## Download dependencies
	go mod download
	go mod tidy

# Install development tools
install-tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Quick development cycle
dev: fmt vet test ## Run fmt, vet, and test (quick development cycle)

# Full CI pipeline
ci: fmt vet lint test-ci ## Run full CI pipeline (fmt, vet, lint, test with coverage)

# Coverage thresholds
coverage-check: test-coverage ## Check if coverage meets minimum threshold
	@go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//' | \
	awk '{if($$1 < 80) {print "Coverage " $$1 "% is below minimum 80%"; exit 1} else {print "Coverage " $$1 "% meets minimum threshold"}}'

# Benchmark tests
bench: ## Run benchmark tests
	go test -bench=. -benchmem ./...

# Generate test reports
test-report: ## Generate detailed test report
	go test -v -coverprofile=coverage.out -json ./... > test-report.json
	go tool cover -func=coverage.out > coverage-summary.txt
	@echo "Test report generated: test-report.json"
	@echo "Coverage summary: coverage-summary.txt"