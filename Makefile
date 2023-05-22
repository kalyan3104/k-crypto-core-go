test:
	@echo "  >  Running unit tests"
	go test -cover -race -coverprofile=coverage.txt -covermode=atomic -v ./...

benchmark-multisig:
	cd signing/mcl/multisig/ && \
		go test -v -bench=. -count 1 -run=^#

