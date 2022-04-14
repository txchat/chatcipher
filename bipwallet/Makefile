PKG_LIST := `go list ./... | grep -v "vendor"`

all:

fmt:
	@go fmt ./...
	@$$(find . -name '*.go' -not -path "./vendor/*" | xargs goimports -l -w)

testall:
	go test -parallel 1 -race $(PKG_LIST)
