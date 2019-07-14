ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TARGET_BINARY := prometheus-emcecs-exporter
BUILD_TIME?=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
RELEASE?=$(shell git describe --abbrev=4 --dirty --always --tags)
COMMIT?=$(shell git rev-parse --short HEAD)

all: clean build

build:
	GO111MODULE=on go build -o bin/${TARGET_BINARY} \
		-ldflags="-X main.commit=${COMMIT} \
		-X main.date=${BUILD_TIME} \
		-X main.version=${RELEASE}" \
		./cmd

goreleaser:
	goreleaser --snapshot --skip-publish --rm-dist

clean:
	for file in bin/$(TARGET_BINARY); do \
		if [ -e "$$file" ]; then \
			rm -f "$$file" || exit 1; \
		fi \
	done
	if [ -e "./dist" ]; then \
		rm -rf ./dist; \
	fi