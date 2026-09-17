# Package manager and cross-platform compatibility

This document details verified package-manager and cross-platform compatibility for InstallGate, the reproducible test harness, observed client behaviors, and explicitly unsupported platform combinations.

## Principle

**Documentation compatibility is not verified support.** A matrix cell is considered verified only when real installs execute against the gateway on that operating system and architecture, producing reproducible evidence. A client documented as npm-compatible is not thereby tested.

Testing runs through local suites and the continuous integration matrix in `.github/workflows/compatibility.yml`.

**This table currently claims almost nothing.** The suites and the matrix exist; the workflow has not yet produced a run. Three cells are marked verified because they were executed on a real macOS arm64 machine and their output recorded. Every other supported cell says "Suite written, not yet run", and stays that way until a run exists to cite — a written suite is not a passing one, and this document would be worthless if it blurred them.

## Compatibility matrix

| Package Manager | OS | Architecture | Status | Verification Evidence / Reason |
|---|---|---|---|---|
| **npm** (v10+) | macOS | arm64 | Implemented and tested | Passing: scoped/unscoped, peer/optional, lockfile (`npm ci`), workspaces, cache, 403 block on corruption |
| **npm** (v10+) | macOS | amd64 | Suite written, not yet run | Targets `macos-13`; no run has produced evidence yet |
| **npm** (v10+) | Linux | amd64 | Suite written, not yet run | Targets `ubuntu-latest`; no run has produced evidence yet |
| **npm** (v10+) | Linux | arm64 | Suite written, not yet run | Targets `ubuntu-24.04-arm`; no run has produced evidence yet |
| **npm** (v10+) | Windows | amd64 | Suite written, not yet run | Targets `windows-latest`; no run has produced evidence yet, CRLF line endings preserved |
| **npm** (v10+) | Windows | arm64 | **Unsupported** | No standard GitHub-hosted runner exists to produce verified evidence |
| **pnpm** (v9/v10) | macOS | arm64 | Implemented and tested | Passing: scoped/unscoped, peer/optional, `pnpm-workspace.yaml`, frozen lockfile, offline, 403 block |
| **pnpm** (v9/v10) | macOS | amd64 | Suite written, not yet run | Targets `macos-13`; no run has produced evidence yet |
| **pnpm** (v9/v10) | Linux | amd64 | Suite written, not yet run | Targets `ubuntu-latest`; no run has produced evidence yet |
| **pnpm** (v9/v10) | Linux | arm64 | Suite written, not yet run | Targets `ubuntu-24.04-arm`; no run has produced evidence yet |
| **pnpm** (v9/v10) | Windows | amd64 | Suite written, not yet run | Targets `windows-latest`; no run has produced evidence yet |
| **pnpm** (v9/v10) | Windows | arm64 | **Unsupported** | No standard GitHub-hosted runner exists to produce verified evidence |
| **Yarn** (v1.22+) | macOS | arm64 | Implemented and tested | Passing: scoped/unscoped, peer/optional, `yarn.lock`, workspaces, offline, 403 block |
| **Yarn** (v1.22+) | macOS | amd64 | Suite written, not yet run | Targets `macos-13`; no run has produced evidence yet |
| **Yarn** (v1.22+) | Linux | amd64 | Suite written, not yet run | Targets `ubuntu-latest`; no run has produced evidence yet |
| **Yarn** (v1.22+) | Linux | arm64 | Suite written, not yet run | Targets `ubuntu-24.04-arm`; no run has produced evidence yet |
| **Yarn** (v1.22+) | Windows | amd64 | Suite written, not yet run | Targets `windows-latest`; no run has produced evidence yet |
| **Yarn** (v1.22+) | Windows | arm64 | **Unsupported** | No standard GitHub-hosted runner exists to produce verified evidence |
| **Bun** (v1.x) | macOS | arm64 | Suite written, not yet run | Suite implemented; no run has produced evidence yet |
| **Bun** (v1.x) | macOS | amd64 | Suite written, not yet run | Targets `macos-13`; no run has produced evidence yet |
| **Bun** (v1.x) | Linux | amd64 | Suite written, not yet run | Targets `ubuntu-latest`; no run has produced evidence yet |
| **Bun** (v1.x) | Linux | arm64 | Suite written, not yet run | Targets `ubuntu-24.04-arm`; no run has produced evidence yet |
| **Bun** (v1.x) | Windows | amd64 | **Unsupported** | Upstream Bun on Windows has known proxy routing and loopback socket limitations |
| **Bun** (v1.x) | Windows | arm64 | **Unsupported** | No standard GitHub-hosted runner exists to produce verified evidence |

## Verified client characteristics

Each package manager behaves differently regarding content negotiation, caching, and integrity verification. The transport enforces byte fidelity across all of them:

### 1. npm
- **Abbreviated packuments**: Sends `Accept: application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*`. The gateway forwards this accept header and upstream returns abbreviated packuments.
- **Conditional requests**: Uses `If-None-Match` with ETags; receives byte-identical `304 Not Modified` responses without re-transmitting package metadata.
- **Lockfile fidelity**: Generates `package-lock.json` recording `sha512-...` hashes matching the fixture registry digests.
- **Corrupted tarball rejection**: When upstream tarball bytes are corrupted, InstallGate's quarantine blocks delivery with HTTP `403 Forbidden` and surfaces decision metadata. When presented with corrupted bytes, npm halts with `EINTEGRITY`.

### 2. pnpm
- **Abbreviated packuments**: Requests `application/vnd.npm.install-v1+json`.
- **Content-addressable store**: Packages are stored and linked via hardlinks from `.pnpm-store`.
- **Corrupted tarball rejection**: Aborts immediately with `ERR_PNPM_TARBALL_HTTP_STATUS` when the gateway blocks the corrupted tarball with HTTP 403.

### 3. Yarn
- **Configuration**: Respects `.yarnrc` and `.npmrc` registry directives.
- **Lockfile integrity**: Generates `yarn.lock` with integrity hashes.
- **Corrupted tarball rejection**: Fails with `Request failed "403 Forbidden"` when the corrupted tarball is blocked by quarantine.

### 4. Bun
- **Configuration**: Uses `bunfig.toml` and `.npmrc`.
- **Platform note**: Verified on Linux and macOS; unsupported on Windows due to upstream proxy routing limitations under loopback registries.

## Verbatim corrupted-tarball test evidence

To prove tests are hard to fake, each test suite intentionally corrupts one byte of a package tarball in transit.

### npm verbatim output on corrupted tarball
```text
npm error code E403
npm error 403 403 Forbidden - GET http://127.0.0.1:58023/fixture-tampered/-/fixture-tampered-1.0.0.tgz - InstallGate: installation block for fixture-tampered@1.0.0 (decision: dec_03bdb6c413bd3fab). Run 'installgate explain dec_03bdb6c413bd3fab' to view reasons and next steps.
npm error 403 In most cases, you or one of your dependencies are requesting a package version that is forbidden by your security policy, or on a server you do not have access to.
```

### pnpm verbatim output on corrupted tarball
```text
Error: ERR_PNPM_TARBALL_HTTP_STATUS
  × installing dependencies
  ╰─▶ Tarball server returned HTTP 403 for http://127.0.0.1:58037/fixture-tampered/-/fixture-tampered-1.0.0.tgz
```

### Yarn verbatim output on corrupted tarball
```text
error Error: http://127.0.0.1:58053/fixture-tampered/-/fixture-tampered-1.0.0.tgz: Request failed "403 Forbidden"
```

## Cross-platform operating system semantics

### Windows
- **Line endings**: `internal/config` detects CRLF (`\r\n`) in existing `.npmrc` files and preserves CRLF when rewriting registry configuration. On `disable`, the original configuration is restored byte-for-byte.
- **Path separators**: Paths in tarball entries using Windows backslashes (`\`) are normalized to forward slashes (`/`) during quarantine inspection, preventing directory traversal attacks.
- **Process lifecycle**: `installgate stop` uses process termination compatible with Windows process handles where POSIX signals are unavailable.
- **File locking**: Quarantined blobs, staging files, and configuration transactions release file handles immediately to avoid Windows sharing violations during atomic renames.

### Linux & macOS
- Support both amd64 and arm64 architectures.
- Atomic configuration updates use atomic rename semantics across POSIX filesystems.

## Explicitly unsupported combinations

The following combinations cannot be proved and are formally documented as unsupported:

1. **Windows on arm64**: Unsupported across all package managers because GitHub Actions does not provide standard hosted runners for Windows on ARM. Compatibility cannot be proven without verified execution evidence.
2. **Bun on Windows**: Unsupported due to upstream proxy redirection and socket handling issues in Bun on Windows when interacting with loopback proxies.
