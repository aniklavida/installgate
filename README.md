# InstallGate

**Nothing executes unchecked.**

InstallGate is an open-source, local-first npm registry firewall for developers and teams using human or AI-driven coding workflows. Once configured, the same dependency policy applies whether a package install was started by a developer, a script, or an autonomous coding agent.

## Project status

InstallGate is in active pre-release development. It is not ready to protect real package installs yet.

Implemented and tested in the current foundation:

- typed `allow`, `warn`, `approval_required`, and `block` verdicts;
- deterministic balanced and strict policy rules for the first high-risk signal combinations;
- npm registry request classification for package metadata and tarball routes;
- a small `doctor` command and automated Go checks.

Planned for v1.0:

- a local public-npm registry gateway;
- content-addressed tarball quarantine before package-manager delivery;
- integrity verification and bounded static inspection without executing package code;
- explainable evidence from package history, advisories, provenance changes, name confusion, and install-time behaviour;
- verified npm, pnpm, Yarn, and Bun support on macOS, Linux, and Windows (see [Compatibility matrix](docs/COMPATIBILITY.md)).

Private registries, other package ecosystems, a web dashboard, cloud accounts, AI-generated security verdicts, Windows on arm64, and Bun on Windows are unsupported in v1.0.

## Why an install-path guard

A scanner only helps when somebody remembers to run it. InstallGate is designed to sit on the registry path so normal and agent-run installs cross one persistent boundary. Known-good cached decisions should remain quiet and fast; suspicious decisions should stop with evidence and a clear next action.

The promise is deliberately precise: the gateway may fetch a tarball into quarantine for inspection, but package bytes that require inspection must not reach the package manager before policy completes.

## Foundation commands

```bash
go test ./...
go run ./cmd/installgate version
go run ./cmd/installgate doctor
```

These commands validate the foundation only. They do not enable a registry proxy.

## Documentation

- [Specification](docs/SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Compatibility matrix](docs/COMPATIBILITY.md)
- [Roadmap](docs/ROADMAP.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
