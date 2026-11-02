GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
export GOCACHE GOMODCACHE
.DEFAULT_GOAL := build

WEB_SOURCES := $(shell find web/src -type f)

.PHONY: build proxy-build capture-build frontend frontend-check test test-race vet fixtures-check packaging-check publication-check clean
frontend: web/dist/index.html
frontend-check:
	node --experimental-strip-types --test web/src/metricHistory.test.ts web/src/logHistory.test.ts web/src/proxyTypes.test.ts web/src/packetTypes.test.ts web/src/flowTypes.test.ts web/src/directoryBrowserState.test.ts
web/node_modules/.package-lock.json: web/package.json web/package-lock.json
	cd web && npm ci
web/dist/index.html: $(WEB_SOURCES) web/index.html web/tsconfig.json web/vite.config.ts web/node_modules/.package-lock.json
	cd web && npm run build
build: frontend
	go build -trimpath -o bin/ctf-manager ./cmd/ctf-manager
proxy-build:
	go build -trimpath -o bin/ctfm-proxy ./cmd/ctfm-proxy
	go build -trimpath -o bin/ctfm-traffic ./cmd/ctfm-traffic
capture-build:
	go build -trimpath -o bin/ctfm-capture ./cmd/ctfm-capture
	go build -trimpath -o bin/ctfm-packets ./cmd/ctfm-packets
test: frontend
	go test ./internal/... ./cmd/...
test-race: frontend
	go test -race ./internal/... ./cmd/...
vet: frontend
	go vet ./internal/... ./cmd/...
packaging-check:
	python3 -m unittest discover -s tests/packaging -p 'test_*.py'
publication-check:
	python3 scripts/check-publication.py
fixtures-check:
	python3 -m unittest discover -s tests/fixtures -p 'test_*.py'
	python3 -m unittest discover -s tests/fixtures/app -p 'test_*.py'
	python3 -m unittest discover -s tests/real-services -p 'test_*.py'
clean:
	rm -f bin/ctf-manager bin/ctfm-proxy bin/ctfm-traffic bin/ctfm-capture bin/ctfm-packets
