# Package manager and cross-platform compatibility

This document details verified package-manager and cross-platform compatibility for InstallGate, the reproducible test harness, observed client behaviors, and explicitly unsupported platform combinations.

## Principle

**Documentation compatibility is not verified support.** A matrix cell is considered verified only when real installs execute against the gateway on that operating system and architecture, producing reproducible evidence. A client documented as npm-compatible is not thereby tested.

Testing runs through local suites and the continuous integration matrix in `.github/workflows/compatibility.yml`.

**The macOS amd64 cells had never run at all, and could not have.** The matrix named `macos-13`, a runner image GitHub retired in December 2025. Jobs naming a retired label are never scheduled — they sit queued indefinitely, which also stops the whole matrix reaching a conclusion and keeps its logs unavailable. Four runs sat queued this way before anyone looked. The matrix now targets `macos-15-intel`, the replacement x86_64 label. Note that GitHub has said Intel macOS runners go away entirely when the macOS 15 image retires, so this column has a known expiry.

**The matrix has now produced a run, and the table cites it.** Every supported cell below was verified by [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975): the compatibility-suites step succeeded on all five platforms, 35 tests each. Before that run this table said "Suite written, not yet run" for almost every cell, because a written suite is not a passing one and the document would be worthless if it blurred them. The same rule still applies to anything added from here.

**One caveat is recorded in the cell rather than hidden:** Bun's workspace test skips on Windows, and says why.

**The CLI enable/disable lifecycle now passes on all five platforms, Windows included** ([run 35223006798](https://github.com/aniklavida/installgate/actions/runs/35223006798)). It had never passed on Windows before, and the cause was the workflow rather than the product: it built the test binary as `installgate_ci_bin` with no extension. `installgate start` re-execs itself through `os.Executable()`, and Go's Windows exec refuses a path with no recognised extension, so `start` failed with `executable file not found in %PATH%` while `status` — invoked directly by bash — worked. No real distribution ships an extensionless Windows binary. With the binary named `.exe`, the Windows run shows the gateway starting on `http://127.0.0.1:8945`, `enable npm` repointing the registry at it, and `disable npm` restoring the original.

## Compatibility matrix

| Package Manager | OS | Architecture | Status | Verification Evidence / Reason |
|---|---|---|---|---|
| **npm** (v10+) | macOS | arm64 | Implemented and tested | All 7 npm tests passing on `macos-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **npm** (v10+) | macOS | amd64 | Implemented and tested | All 7 npm tests passing on `macos-15-intel` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **npm** (v10+) | Linux | amd64 | Implemented and tested | All 7 npm tests passing on `ubuntu-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **npm** (v10+) | Linux | arm64 | Implemented and tested | All 7 npm tests passing on `ubuntu-24.04-arm` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **npm** (v10+) | Windows | amd64 | Implemented and tested | All 7 npm tests passing on `windows-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **npm** (v10+) | Windows | arm64 | **Unsupported** | No standard GitHub-hosted runner exists to produce verified evidence |
| **pnpm** (v9/v10) | macOS | arm64 | Implemented and tested | All 6 pnpm tests passing on `macos-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **pnpm** (v9/v10) | macOS | amd64 | Implemented and tested | All 6 pnpm tests passing on `macos-15-intel` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **pnpm** (v9/v10) | Linux | amd64 | Implemented and tested | All 6 pnpm tests passing on `ubuntu-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **pnpm** (v9/v10) | Linux | arm64 | Implemented and tested | All 6 pnpm tests passing on `ubuntu-24.04-arm` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **pnpm** (v9/v10) | Windows | amd64 | Implemented and tested | All 6 pnpm tests passing on `windows-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **pnpm** (v9/v10) | Windows | arm64 | **Unsupported** | No standard GitHub-hosted runner exists to produce verified evidence |
| **Yarn** (v1.22+) | macOS | arm64 | Implemented and tested | All 6 Yarn tests passing on `macos-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Yarn** (v1.22+) | macOS | amd64 | Implemented and tested | All 6 Yarn tests passing on `macos-15-intel` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Yarn** (v1.22+) | Linux | amd64 | Implemented and tested | All 6 Yarn tests passing on `ubuntu-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Yarn** (v1.22+) | Linux | arm64 | Implemented and tested | All 6 Yarn tests passing on `ubuntu-24.04-arm` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Yarn** (v1.22+) | Windows | amd64 | Implemented and tested | All 6 Yarn tests passing on `windows-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Yarn** (v1.22+) | Windows | arm64 | **Unsupported** | No standard GitHub-hosted runner exists to produce verified evidence |
| **Bun** (v1.x) | macOS | arm64 | Implemented and tested | All 6 Bun tests passing on `macos-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Bun** (v1.x) | macOS | amd64 | Implemented and tested | All 6 Bun tests passing on `macos-15-intel` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Bun** (v1.x) | Linux | amd64 | Implemented and tested | All 6 Bun tests passing on `ubuntu-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Bun** (v1.x) | Linux | arm64 | Implemented and tested | All 6 Bun tests passing on `ubuntu-24.04-arm` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) |
| **Bun** (v1.x) | Windows | amd64 | Implemented and tested, one skip | 5 of 6 Bun tests passing on `windows-latest` in [run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975). `TestBun_Workspaces` skips: bun cannot create the workspace symlink without Developer Mode. The same run shows the gateway had already served every package before bun failed, so this is a client-side limitation, not a gateway one. This cell previously read **Unsupported**, citing "proxy routing and loopback socket limitations" — the run disproves that. |
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

The following combinations cannot be proved and are formally documented as unsupported. An entry stays here only while no run contradicts it:

1. **Windows on arm64**: Unsupported across all package managers because GitHub Actions does not provide standard hosted runners for Windows on ARM. Compatibility cannot be proven without verified execution evidence.
2. **~~Bun on Windows~~ — withdrawn.** This entry claimed Bun was unsupported on Windows "due to upstream proxy redirection and socket handling issues ... when interacting with loopback proxies." [Run 35222014975](https://github.com/aniklavida/installgate/actions/runs/35222014975) disproves it: five of six Bun tests pass on `windows-latest`, including the scoped/unscoped install, lockfile, cache and corrupted-tarball cases, all of them going through the loopback gateway. The one remaining gap is `TestBun_Workspaces`, which skips because bun cannot create a workspace symlink without Developer Mode — a Windows privilege limitation in the client, unrelated to proxying. The matrix row records it.
