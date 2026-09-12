# v1.0 release checklist

No item may be inferred from documentation or partial implementation. Record reproducible evidence for every completed check.

## Product behaviour

- [ ] Normal installs preserve verified upstream integrity through the gateway.
- [ ] Nonexistent packages fail without being labelled malicious.
- [ ] A synthetic newborn/confusable package is held with explainable evidence.
- [ ] A dangerous install script is blocked before the package manager receives the tarball.
- [ ] A known vulnerable version is blocked with a verified alternative when one exists.
- [ ] Balanced and strict evidence-outage behaviour matches policy.
- [ ] MCP and gateway decisions match for the same evidence snapshot.

## Compatibility and recovery

- [ ] npm, pnpm, Yarn, and Bun pass on macOS, Linux, and Windows.
- [ ] Signed macOS, Linux, and Windows binaries exist for amd64 and arm64.
- [ ] Enable and disable restore the exact prior registry configuration.
- [ ] Interrupted configuration, migrations, quarantine, and restart paths recover safely.
- [ ] Backup, restore, and cache rebuild are demonstrated.

## Security and privacy

- [ ] Archive traversal, symlink escape, archive-bomb, size, count, and timeout tests pass.
- [ ] Integrity is checked before inspection and before release.
- [ ] No test executes package code during inspection.
- [ ] Logs and audit exports contain no credentials, authorization headers, secrets, or package contents.
- [ ] Human-only expiring approvals cannot be created through MCP.
- [ ] Security review and private vulnerability-reporting flow are complete.

## Release proof

- [ ] Clean installation succeeds in fresh supported environments.
- [ ] Public documentation matches implemented and tested behaviour.
- [ ] CI is green on the release commit.
- [ ] A 60–90 second end-to-end demo is available.
- [ ] Changelog and migration notes are complete.
- [ ] Tag and release artifacts are reproducible and signed.
