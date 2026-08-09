# dependaSNORT — developer tasks. (Unix shells / WSL / Git Bash. On Windows
# PowerShell, use the plain `go` commands from the README.)

BINARY  := depsnort
PKG     := ./cmd/depsnort
VERSION ?= v0.6.1
LDFLAGS := -X main.version=$(VERSION)

# CGO is disabled: dependaSNORT is a single static binary with no libc linkage
# (Decision D-10). This also avoids the missing-C-headers trap on minimal Linux.
export CGO_ENABLED := 0

.PHONY: build test vet fmt fmtcheck run checks self-audit clean \
       org-scan priority

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmtcheck:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

run: build
	./$(BINARY) scan internal/ecosystem/npm/testdata/proj

run-all: build
	@echo "--- npm ---"
	./$(BINARY) scan -no-osv -no-registry internal/ecosystem/npm/testdata/proj
	@echo "--- rubygems ---"
	./$(BINARY) scan -no-osv -no-registry internal/ecosystem/rubygems/testdata
	@echo "--- cargo ---"
	./$(BINARY) scan -no-osv -no-registry internal/ecosystem/cargo/testdata
	@echo "--- composer ---"
	./$(BINARY) scan -no-osv -no-registry internal/ecosystem/composer/testdata
	@echo "--- nuget ---"
	./$(BINARY) scan -no-osv -no-registry internal/ecosystem/nuget/testdata

checks: build
	./$(BINARY) checks

# Dogfood proof (Decision D-10): the module graph must be a single line — the
# module itself, with no third-party dependencies.
self-audit:
	@echo "module dependency graph (want exactly one line):"
	@go list -m all

# --- Python tooling (stdlib only, no pip install) ---

# Fleet scan: enumerate an org or target list and run isolated per-project scans.
#   make org-scan TARGET=org:myorg
#   make org-scan TARGET=list:repos.txt
#   make org-scan TARGET=./local/dir
ORG_OUT     ?= ./depsnort-org-out
ORG_ARGS    ?=
org-scan: build
	python tools/depsnort_org.py $(TARGET) -o $(ORG_OUT) --depsnort ./$(BINARY) $(ORG_ARGS)

# Remediation priority: rank findings by CI/CD blast radius.
#   make priority SCANS="./depsnort-org-out/scans/*.json"
SCANS       ?= ./depsnort-org-out/scans/*.json
PRI_OUT     ?= priority.json
PRI_ARGS    ?=
priority:
	python tools/depsnort_priority.py $(SCANS) -o $(PRI_OUT) $(PRI_ARGS)

clean:
	rm -f $(BINARY)
