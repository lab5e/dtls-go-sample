all: sample

sample: 
	@go build -ldflags="-X main.Version=$(cat release/VERSION)"


releases:
	@GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Version=$(cat release/VERSION)" -o bin/dtls-go-sample.amd64-linux
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.Version=$(cat release/VERSION)" -o bin/dtls-go-sample.amd64-macOS
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.Version=$(cat release/VERSION)" -o bin/dtls-go-sample.arm64-macOS
	@GOOS=windows GOARCH=amd64 go build -ldflags="-X main.Version=$(cat release/VERSION)" -o bin/dtls-go-sample.amd64-win.exe
