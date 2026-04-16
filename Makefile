.PHONY: all build test test-verbose coverage clean fmt vet lint tidy check deps verify help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Binary name
BINARY_NAME=ztts
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html

# Binary output directory
BIN_DIR=bin

# Packages
PACKAGES=$(shell $(GOCMD) list ./...)

all: test build ## Run tests and build

build: ## Build the server binary
	@echo "Building..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -v -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/ztts

build-lib: ## Build the library (verify all packages compile)
	@echo "Building library..."
	$(GOBUILD) -v ./...

test: ## Run tests with race detection
	@echo "Running tests..."
	$(GOTEST) -v -race -count=1 ./...

test-short: ## Run tests in short mode
	@echo "Running tests (short mode)..."
	$(GOTEST) -short ./...

coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	$(GOTEST) -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"

coverage-cli: ## Show test coverage in terminal
	@echo "Generating coverage report..."
	$(GOTEST) -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GOCMD) tool cover -func=$(COVERAGE_FILE)

clean: ## Remove build artifacts and coverage reports
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	rm -rf $(BIN_DIR)/
	rm -f *.log

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) ./...

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...

lint: fmt vet ## Run all linters

tidy: ## Tidy go modules
	@echo "Tidying go modules..."
	$(GOMOD) tidy

check: fmt vet test ## Format, vet, and test

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download

verify: ## Verify dependencies
	@echo "Verifying dependencies..."
	$(GOMOD) verify

setup: ## Set up development environment (install hooks)
	@echo "Setting up development environment..."
	@bash scripts/setup-dev.sh

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
