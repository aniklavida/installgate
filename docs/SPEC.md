# InstallGate specification

## Product promise

InstallGate is a local-first npm registry firewall. It ensures dependency requests cross one persistent, explainable policy boundary before package-manager execution.

The precise promise is: **nothing executes unchecked**. A package tarball may be fetched into an isolated quarantine for inspection, but bytes requiring inspection must not reach the package manager until the policy decision completes.

## Primary users and jobs

- Developers using coding agents who need protection even when the agent runs the install command.
- Developers who want protection from plausible invented or confusing package names.
- Teams that need one reviewable policy plus machine-local approvals and audit history.
- Maintainers who want risky new versions held while known-good versions remain usable.

## Required v1.0 behaviour

### Registry gateway

- Proxy public npm metadata and tarball `GET` and `HEAD` requests for scoped and unscoped packages.
- Preserve supported content negotiation, conditional requests, status codes, redirects, and integrity metadata.
- Configure and restore npm registry settings atomically.
- Verify npm, pnpm, Yarn, and Bun compatibility.
- Reject publication, mutation, private-registry, and other unsupported flows clearly.

### Quarantine and inspection

- Download tarballs that need deep inspection into a content-addressed quarantine.
- Verify upstream integrity before inspection and again before release.
- Prevent path traversal, symlink escape, archive bombs, excessive file counts, and oversized entries.
- Never execute package code.
- Inspect bounded static surfaces for install scripts, native builds, process/network/credential access, obfuscation, and staged payload indicators.

### Evidence and policy

- Collect package/version existence and history, advisories, maintainer and provenance changes, fresh/newborn signals, strong name confusion, and install-time behaviour.
- Preserve evidence source, observation, retrieval time, confidence, and freshness.
- Return deterministic `allow`, `warn`, `approval_required`, or `block` decisions.
- Include balanced and strict profiles plus validated repository-local policy.
- Never treat low popularity, a missing repository, or missing evidence alone as proof of maliciousness.
- Never describe a positive result as proof that a package is safe.
- Require expiring, attributable human approvals; an agent cannot approve its own dependency.

### Interfaces and state

- Provide CLI lifecycle, preflight, explanation, policy, approval, audit, cache, backup, and diagnostic commands.
- Provide read-only/preflight MCP tools that use the same policy engine and evidence snapshot as the gateway.
- Store configuration history, evidence metadata, decisions, approvals, and append-only audit events in embedded SQLite.
- Store quarantined archives in a content-addressed blob store.
- Use ordered migrations and crash-safe transitions; provide backup, restore, and cache-rebuild paths.
- Collect no telemetry and never persist npm credentials or full authorization headers.

## Default policy intent

Integrity mismatch and known malicious evidence block in every profile. Vulnerabilities above the configured threshold block. Strong name confusion corroborated by package freshness, or a publisher/provenance change combined with a new install script, requires approval in balanced mode and blocks in strict mode. An install script alone warns in balanced mode and requires approval in strict mode. Evidence outages degrade explicitly according to cache freshness and profile.

## Quality requirements

- Identical policy, input, and evidence snapshots produce identical verdicts and reasons.
- Audit data can reconstruct the rule and evidence snapshot behind a decision.
- Package bytes do not reach the package manager until all required checks complete.
- Archive work and remote calls enforce explicit limits and timeouts.
- Cached known-good decisions target no more than 50 ms p95 overhead on the release test machine.
- Restarts preserve approvals and audit history.

## Unsupported in v1.0

Other package ecosystems, private/authenticated npm registries, publication and mutations, general application-code scanning, automatic source rewriting, cloud accounts, a web dashboard, AI-generated verdicts, and remote or agent-controlled approval.
