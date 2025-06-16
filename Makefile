.PHONY: test
test:
	@echo "Running tests..."
	go test -v -race ./...
.PHONY: test-e2e
test-e2e:
	@echo "Running tests..."
	go test -v -race -tags e2e ./tests/e2e/...

.PHONY: lint
lint:
	golangci-lint run ./...