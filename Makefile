ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TARGET_BINARY := prometheus-emcecs-exporter
BUILD_TIME?=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
RELEASE?=$(shell git describe --abbrev=4 --dirty --always --tags)
COMMIT?=$(shell git rev-parse --short HEAD)

all: build

build:
	GO111MODULE=on go build -o bin/${TARGET_BINARY} \
		-ldflags="-X main.Commit=${COMMIT} \
		-X main.BuildTime=${BUILD_TIME} \
		-X main.Release=${RELEASE}" \
		./cmd