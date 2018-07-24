all: build

build:
	dep ensure
	go test
	go build

