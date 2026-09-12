# Contributing

InstallGate welcomes focused bug reports, tests, documentation improvements, and implementation contributions that fit the accepted v1.0 boundary.

## Before opening a pull request

1. Open or reference an issue for material behaviour changes.
2. Keep one pull request focused on one concern.
3. Add or update tests for behaviour changes.
4. Run:

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build ./cmd/installgate
```

5. Confirm documentation does not claim planned behaviour is already supported.

## Security-sensitive changes

Changes to archive handling, integrity checks, policy evaluation, approvals, credentials, audit records, or registry protocol handling need explicit threat-focused tests. Do not include real secrets or malicious payloads in fixtures.

By contributing, you agree that your contribution is licensed under Apache License 2.0.
