BIN := leakguard

.PHONY: build test install scan hook
build:
	go build -o $(BIN) ./cmd/leakguard
test:
	go test ./... -v
install:
	go install ./cmd/leakguard
scan: build
	./$(BIN) scan .
hook: install
	leakguard install-hook
