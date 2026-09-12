# Contributor instructions

These instructions apply to every automated or human contributor in this repository.

## Build and test

Run before submitting a change:

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build ./cmd/installgate
```

## Engineering rules

- Keep policy evaluation deterministic and side-effect free.
- Preserve explicit evidence provenance and freshness in every decision reason.
- Never execute package contents during inspection.
- Never log credentials, authorization headers, package tokens, or package contents.
- Treat unavailable evidence as unavailable, never as proof that a package is safe.
- Keep gateway, CLI, and MCP decisions on the same core engine.
- Add tests for every policy or registry-routing change.
- Describe capabilities truthfully as implemented and tested, experimental, planned for v1.0, or unsupported.

## Scope

Do not add another package ecosystem, private registry support, cloud service, web dashboard, or autonomous approval path without an accepted design decision. Keep changes narrow and reviewable.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow.
