all: sample

sample: 
	@go build -ldflags="-X main.Version=$(cat release/VERSION)"


