# golang1.9 or latest
# 1. make help
# 2. make dep
# 3. make build
# ...

NAME := cipher4py.so
BUILD_DIR := build
APP := ${BUILD_DIR}/${NAME}

.PHONY: clean build

clean: ## Remove previous build
	@rm -rf ${BUILD_DIR}
	@go clean

build: #checkgofmt ## Build the binary file
	GOOS=linux GOARCH=amd64 GO111MODULE=on GOPROXY=https://goproxy.cn,direct GOSUMDB="sum.golang.google.cn" go build -buildmode=c-shared -o $(APP) main.go