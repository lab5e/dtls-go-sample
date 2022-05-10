all: sample

ifeq ($(VERSION),)
VERSION := $(shell git tag -l --sort=-version:refname | head -n 1 | cut -c 2-)
endif

sample: 
	@echo "Building version $(VERSION)"
	@go build -ldflags="-X main.Version=$(VERSION)"


releases:
	@GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o bin/dtls-go-sample.amd64-linux
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o bin/dtls-go-sample.amd64-macOS
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.Version=$(VERSION)" -o bin/dtls-go-sample.arm64-macOS
	@GOOS=windows GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION)" -o bin/dtls-go-sample.amd64-win.exe
