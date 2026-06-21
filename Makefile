.PHONY: all build install test clean run

# Build the PQC client
build:
	@echo "Building PQC client..."
	@go build -o bin/pqc-chart-tool ./cmd/pqc-chart-tool
	@echo "Build complete: bin/pqc-chart-tool"

# Install the PQC client
install: build
	@echo "Installing PQC client..."
	@go install ./cmd/pqc-chart-tool

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Generate ID hash
generate-id:
	@echo "Generating new identity..."
	@./bin/pqc-chart-tool generate

# Show ID hash
show-id:
	@echo "Showing ID hash..."
	@./bin/pqc-chart-tool show-id

# Default target
all: build

# Help
help:
	@echo "Available targets:"
	@echo "  make all          - Build everything (default)"
	@echo "  make build        - Build the PQC client"
	@echo "  make install      - Install the PQC client"
	@echo "  make test         - Run tests"
	@echo "  make test-coverage- Run tests with coverage"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Run linter"
	@echo "  make generate-id  - Generate new identity"
	@echo "  make show-id      - Show ID hash"
