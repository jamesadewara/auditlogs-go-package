# Releasing

Go modules are published by pushing a version tag; there is no upload step.

## Check

```bash
gofmt -l .          # must print nothing
go vet ./...
go test ./...
```

## Release

1. Set `Version` in `verify/version.go` and add a `CHANGELOG.md` entry for it.
2. Commit, then tag with a leading `v` (for `Version = "0.1.0"` the tag is `v0.1.0`) and push the tag.
3. Request the version once so the Go module proxy and pkg.go.dev pick it up:

```bash
GOPROXY=https://proxy.golang.org go list -m github.com/jamesadewara/auditlogs-go-package@v0.1.0
```

## Smoke-test the command

```bash
go install github.com/jamesadewara/auditlogs-go-package/cmd/auditlogs-verify@v0.1.0
auditlogs-verify --version
```

A published tag cannot be changed. To fix a bad release, publish a new version and add a
`retract` directive for the bad one in `go.mod`.
