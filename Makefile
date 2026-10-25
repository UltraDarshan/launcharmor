.PHONY: all build test clean run-scan run-db run-harden

BINARY_NAME=vibeshield
BUILD_DIR=bin
CMD_PATH=./cmd/vibeshield

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
