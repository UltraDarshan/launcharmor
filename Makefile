.PHONY: all build test clean run-scan run-db run-harden site

BINARY_NAME=launcharmor
BUILD_DIR=bin
CMD_PATH=./cmd/launcharmor

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

test:
	@echo "Running tests..."
	go test -v ./...

clean:
	@echo "Cleaning artifacts..."
	rm -rf $(BUILD_DIR) deploy

run-scan: build
	./$(BUILD_DIR)/$(BINARY_NAME) scan .

run-db: build
	./$(BUILD_DIR)/$(BINARY_NAME) db-audit .

run-harden: build
	./$(BUILD_DIR)/$(BINARY_NAME) harden myapp 3000 myapp.com ./deploy

# Compile the landing page's Tailwind CSS (docs/ is served by GitHub Pages)
site:
	cd web && npm install --no-audit --no-fund && npm run build
