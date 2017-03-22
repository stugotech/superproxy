PWD=$(shell pwd)
GONAME=$(shell basename "$(PWD)")
GOBIN=$(PWD)/bin
VERSION=$(shell git describe --exact-match 2>/dev/null)
GOOS=linux
GOARCH=amd64
BINFILE=$(GONAME)-$(GOOS)-$(GOARCH)

.PHONY: build docker clean push checkversion

build: checkversion
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -v -o bin/$(BINFILE)

docker: checkversion
	docker build -t eu.gcr.io/stugohome/$(GONAME):$(VERSION) .

push: checkversion
	gcloud docker -- push eu.gcr.io/stugohome/$(GONAME):$(VERSION)

clean:
	rm -rf bin

checkversion:
	@test $(VERSION) || (echo "no version tag" && false)