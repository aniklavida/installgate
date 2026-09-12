# Roadmap to v1.0

Development uses internal milestones. The first marketed release will be a complete, useful v1.0; no disposable v0.x release is planned.

## M0 — Foundation and protocol spike

- [x] Establish repository, documentation, contribution, security, and CI foundation.
- [x] Define verdict/evidence contracts and the first deterministic policy rules.
- [x] Classify npm metadata and tarball request paths.
- [ ] Prove upstream metadata and tarball pass-through without semantic corruption.

## M1 — Evidence and policy

- Implement evidence snapshots, provider interfaces, freshness, and cache semantics.
- Implement complete balanced and strict policy matrices.
- Add exact-version advisory checks, package history, provenance-change, and strong name-confusion evidence.
- Provide stable human and JSON decision explanations.

## M2 — Quarantine and inspection

- Add content-addressed quarantine and double integrity verification.
- Add hardened archive extraction and explicit resource limits.
- Add bounded install-time static inspection without code execution.

## M3 — Product interfaces and state

- Complete registry gateway lifecycle and transactional npm configuration.
- Add SQLite migrations, approvals, audit history, backup, and restore.
- Complete CLI commands and read-only/preflight MCP tools.

## M4 — Compatibility and release proof

- Verify npm, pnpm, Yarn, and Bun across supported operating systems and architectures.
- Complete adversarial security, outage, crash-recovery, privacy, and migration tests.
- Produce signed binaries, optional Docker image, clean-install proof, and a concise demo.
- Publish v1.0 only after every release gate passes.
