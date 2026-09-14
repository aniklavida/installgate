# Architecture

## Current foundation

The repository currently implements and tests:

- shared verdict and evidence types;
- a pure deterministic first policy slice;
- npm metadata and tarball request classification;
- registry gateway lifecycle, transaction journaling, and atomic npm configuration;
- a diagnostic command.

The operational registry firewall is planned for v1.0 and is not implemented yet.

## Target v1.0 components

```text
npm-compatible client
        |
        v
local HTTP gateway -----> upstream public npm registry
        |                           |
        v                           v
request classifier          metadata / tarball fetch
        |                           |
        +------> evidence engine <--+
                       |
                       v
              deterministic policy
                /      |       \
               v       v        v
          SQLite   quarantine   audit log
               \       |        /
                decision response

CLI and MCP call the same evidence and policy core.
```

## Package boundaries

- `internal/gateway`: npm HTTP protocol parsing and upstream transport.
- `internal/evidence`: provider interfaces, caching, freshness, and observations.
- `internal/policy`: pure rule evaluation and profiles.
- `internal/quarantine`: content-addressed storage, integrity, safe extraction, and static inspection.
- `internal/store`: SQLite migrations, decisions, approvals, and audit events.
- `internal/config`: transactional enable/disable and policy loading.
- `internal/mcpserver`: read-only/preflight MCP tools.
- `cmd/installgate`: CLI and service entry point.

## Invariants

1. No package code executes during analysis.
2. Required checks finish before inspected bytes reach the package manager.
3. Policy decisions depend only on explicit input, policy, and an identified evidence snapshot.
4. Missing or stale evidence remains visible in the result.
5. An MCP client cannot create an approval.
6. Credentials and full authorization headers never enter logs or persistent state.

## Planned technology

One Go binary, standard-library HTTP where practical, embedded SQLite, and the official Go MCP SDK. External dependencies are added only when their maintenance and security posture have been checked.
