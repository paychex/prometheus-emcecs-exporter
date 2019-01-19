all: build

build:
	env GO111MODULE=on go test
	env GO111MODULE=on go build 

