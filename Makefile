PWD=$(shell pwd)
GONAME=$(shell basename "$(PWD)")
GOBIN=$(PWD)/bin
VERSION=$(shell git describe)
GOOS=linux
GOARCH=amd64
BINFILE=$(GONAME)-$(GOOS)-$(GOARCH)

.PHONY: build docker clean push

build: 
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -v -o bin/$(BINFILE)

docker: 
	docker build -t eu.gcr.io/stugohome/$(GONAME):$(VERSION) .

push:
	gcloud docker -- push eu.gcr.io/stugohome/$(GONAME):$(VERSION)

clean:
	rm -rf bin