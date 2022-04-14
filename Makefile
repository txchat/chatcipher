fmt: ## go fmt
	@go fmt ./...
	@find . -name '*.go' -not -path "./vendor/*" | xargs goimports -l -w

get:
    @export GO111MODULE=on
    @go get ./...