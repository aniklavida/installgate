package quarantine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestArchiveAdversarial_PathTraversalVectors asserts that every form of path traversal
// in tar archives is rejected immediately without extracting or creating files outside the target.
func TestArchiveAdversarial_PathTraversalVectors(t *testing.T) {
	tempDir := t.TempDir()

	traversalVectors := []struct {
		name string
		path string
	}{
		{"RelativeDotDotSimple", "../outside.txt"},
		{"RelativeDotDotNested", "../../outside.txt"},
		{"RelativeDotDotDeep", "../../../../../../../../../../../tmp/escaped.txt"},
		{"SubdirDotDot", "package/../../escaped.txt"},
		{"SubdirDotDotDeep", "package/a/b/c/../../../../escaped.txt"},
		{"AbsoluteUnix", "/etc/passwd"},
		{"AbsoluteUnixVar", "/var/log/escaped.log"},
		{"WindowsDriveAbsolute", "C:\\Windows\\escaped.dll"},
		{"WindowsDriveRelative", "C:escaped.txt"},
		{"WindowsBackslashTraversal", "..\\..\\escaped.txt"},
		{"WindowsMixedSlashes", "package/..\\../escaped.txt"},
		{"LeadingSlashNormalized", "///escaped.txt"},
		{"DotDotSlashDotDot", "./../../escaped.txt"},
	}

	for _, vec := range traversalVectors {
		t.Run(vec.name, func(t *testing.T) {
			// Verify destination does not exist before inspection
			outsideCanary := filepath.Join(tempDir, "escaped.txt")
			_ = os.Remove(outsideCanary)

			tarball := createTestTarball(t, map[string][]byte{
				vec.path: []byte("malicious content payload"),
			}, nil)

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected error for traversal vector %q, got nil", vec.path)
			}
			if !errors.Is(err, ErrArchivePathTraversal) {
				t.Fatalf("expected ErrArchivePathTraversal, got: %v", err)
			}

			// Assert no file was written outside or inside
			if _, err := os.Stat(outsideCanary); !os.IsNotExist(err) {
				t.Fatalf("CRITICAL SECURITY VULNERABILITY: file was written to %s during traversal test!", outsideCanary)
			}
		})
	}
}

// TestArchiveAdversarial_SymlinkEscapes asserts that symlinks targeting paths
// outside the archive root or referencing absolute system paths are blocked.
func TestArchiveAdversarial_SymlinkEscapes(t *testing.T) {
	tempDir := t.TempDir()

	symlinkVectors := []struct {
		name   string
		source string
		target string
	}{
		{"EscapingParent", "package/link_parent", "../../etc/shadow"},
		{"EscapingParentDeep", "package/a/b/c/link_deep", "../../../../etc/passwd"},
		{"AbsoluteUnixRoot", "package/link_root", "/etc/passwd"},
		{"AbsoluteUnixTmp", "package/link_tmp", "/tmp/sensitive"},
		{"WindowsDriveAbsolute", "package/link_win", "C:\\Windows\\System32"},
		{"WindowsBackslashEscape", "package\\link_win_rel", "..\\..\\sensitive"},
		{"SelfEscapingRoot", "link_root", ".."},
		{"TraversingSelfDir", "package/link_loop", "link_loop/../../etc/passwd"},
	}

	for _, vec := range symlinkVectors {
		t.Run(vec.name, func(t *testing.T) {
			canaryTarget := filepath.Join(tempDir, "sensitive")
			_ = os.Remove(canaryTarget)

			tarball := createTestTarball(t, map[string][]byte{
				"package/package.json": []byte(`{"name":"symlink-escape-test","version":"1.0.0"}`),
			}, map[string]string{
				vec.source: vec.target,
			})

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected error for escaping symlink %s -> %s, got nil", vec.source, vec.target)
			}
			if !errors.Is(err, ErrArchiveSymlinkEscape) {
				t.Fatalf("expected ErrArchiveSymlinkEscape, got: %v", err)
			}

			if _, err := os.Stat(canaryTarget); !os.IsNotExist(err) {
				t.Fatalf("CRITICAL SECURITY VULNERABILITY: target path was modified during symlink test: %s", canaryTarget)
			}
		})
	}
}

// TestArchiveAdversarial_HardlinkEscapes asserts that hardlinks referencing paths
// outside the archive root or absolute locations are rejected.
func TestArchiveAdversarial_HardlinkEscapes(t *testing.T) {
	tempDir := t.TempDir()

	hardlinkVectors := []struct {
		name   string
		source string
		target string
	}{
		{"EscapingParent", "package/hardlink_parent", "../../etc/shadow"},
		{"EscapingParentDeep", "package/a/b/c/hardlink_deep", "../../../../etc/passwd"},
		{"AbsoluteUnixRoot", "package/hardlink_root", "/etc/passwd"},
		{"WindowsBackslashEscape", "package\\hardlink_win", "..\\..\\sensitive"},
	}

	for _, vec := range hardlinkVectors {
		t.Run(vec.name, func(t *testing.T) {
			canaryTarget := filepath.Join(tempDir, "sensitive")
			_ = os.Remove(canaryTarget)

			tarball := createCustomTarball(t, map[string][]byte{
				"package/package.json": []byte(`{"name":"hardlink-escape-test","version":"1.0.0"}`),
			}, nil, map[string]string{
				vec.source: vec.target,
			}, nil)

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected error for escaping hardlink %s -> %s, got nil", vec.source, vec.target)
			}
			if !errors.Is(err, ErrArchiveHardlinkEscape) {
				t.Fatalf("expected ErrArchiveHardlinkEscape, got: %v", err)
			}

			if _, err := os.Stat(canaryTarget); !os.IsNotExist(err) {
				t.Fatalf("CRITICAL SECURITY VULNERABILITY: target path was modified during hardlink test: %s", canaryTarget)
			}
		})
	}
}

// TestArchiveAdversarial_ArchiveBombs asserts safe handling of decompression bombs:
// cumulative uncompressed limit, single entry size limit, and declared giant sizes.
func TestArchiveAdversarial_ArchiveBombs(t *testing.T) {
	t.Run("CumulativeUncompressedBomb", func(t *testing.T) {
		// Total uncompressed size exceeds MaxExtractedBytes
		files := make(map[string][]byte)
		for i := 0; i < 20; i++ {
			files[string(rune('a'+i))+".txt"] = bytes.Repeat([]byte("BOMB"), 100) // 400 bytes each * 20 = 8000 bytes
		}
		tarball := createTestTarball(t, files, nil)

		limits := DefaultArchiveLimits()
		limits.MaxExtractedBytes = 3000 // limit is 3000 bytes

		_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
		if err == nil {
			t.Fatal("expected ErrArchiveBomb, got nil")
		}
		if !errors.Is(err, ErrArchiveBomb) {
			t.Fatalf("expected ErrArchiveBomb, got: %v", err)
		}
	})

	t.Run("SingleEntrySizeLimit", func(t *testing.T) {
		tarball := createTestTarball(t, map[string][]byte{
			"huge_single_file.bin": bytes.Repeat([]byte("X"), 1024),
		}, nil)

		limits := DefaultArchiveLimits()
		limits.MaxFileBytes = 512

		_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
		if err == nil {
			t.Fatal("expected ErrArchiveEntryTooLarge, got nil")
		}
		if !errors.Is(err, ErrArchiveEntryTooLarge) {
			t.Fatalf("expected ErrArchiveEntryTooLarge, got: %v", err)
		}
	})

	t.Run("DeclaredGiantSizeInHeader", func(t *testing.T) {
		// As per constraints: declared petabyte/gigabyte size in tar header without shipping a real bomb
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)

		// Header declares 1 Terabyte (10^12 bytes), but body is empty/small
		hdr := &tar.Header{
			Name:     "package/declared_giant.bin",
			Mode:     0o644,
			Size:     1024 * 1024 * 1024 * 1024, // 1 TiB declared
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed writing header: %v", err)
		}
		_ = tw.Close()
		_ = gw.Close()

		limits := DefaultArchiveLimits()
		limits.MaxFileBytes = 20 * 1024 * 1024 // 20 MiB max

		_, err := InspectArchive(context.Background(), bytes.NewReader(buf.Bytes()), limits)
		if err == nil {
			t.Fatal("expected error for declared giant size header, got nil")
		}
		if !errors.Is(err, ErrArchiveEntryTooLarge) {
			t.Fatalf("expected ErrArchiveEntryTooLarge, got: %v", err)
		}
	})
}

// TestArchiveAdversarial_EntryCountLimit asserts that tarballs with too many entries fail closed.
func TestArchiveAdversarial_EntryCountLimit(t *testing.T) {
	files := make(map[string][]byte)
	for i := 0; i < 50; i++ {
		files[string(rune('A'+(i/26)))+string(rune('a'+(i%26)))+".txt"] = []byte("small")
	}
	tarball := createTestTarball(t, files, nil)

	limits := DefaultArchiveLimits()
	limits.MaxEntryCount = 25

	_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
	if err == nil {
		t.Fatal("expected ErrArchiveTooManyEntries, got nil")
	}
	if !errors.Is(err, ErrArchiveTooManyEntries) {
		t.Fatalf("expected ErrArchiveTooManyEntries, got: %v", err)
	}
}

// TestArchiveAdversarial_Timeout asserts that an inspection exceeding its deadline fails closed.
func TestArchiveAdversarial_Timeout(t *testing.T) {
	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"timeout-pkg","version":"1.0.0"}`),
		"package/index.js":     []byte("module.exports = {};\n"),
	}, nil)

	limits := DefaultArchiveLimits()
	limits.Timeout = 1 * time.Millisecond

	// Sleep-inducing reader or pre-expired context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-10*time.Millisecond))
	defer cancel()

	_, err := InspectArchive(ctx, bytes.NewReader(tarball), limits)
	if err == nil {
		t.Fatal("expected ErrArchiveTimeout, got nil")
	}
	if !errors.Is(err, ErrArchiveTimeout) {
		t.Fatalf("expected ErrArchiveTimeout, got: %v", err)
	}
}

// TestArchiveAdversarial_DuplicateEntriesBlocked asserts that duplicate paths in an archive are rejected.
func TestArchiveAdversarial_DuplicateEntriesBlocked(t *testing.T) {
	tarball := createCustomTarball(t, map[string][]byte{
		"package/index.js": []byte("console.log('first');"),
	}, nil, nil, []string{"package/index.js"})

	limits := DefaultArchiveLimits()
	_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
	if err == nil {
		t.Fatal("expected ErrArchiveDuplicateEntry, got nil")
	}
	if !errors.Is(err, ErrArchiveDuplicateEntry) {
		t.Fatalf("expected ErrArchiveDuplicateEntry, got: %v", err)
	}
}

// TestArchiveAdversarial_NestedArchivesBlocked asserts that nested archive payloads are rejected.
func TestArchiveAdversarial_NestedArchivesBlocked(t *testing.T) {
	nestedPayloads := []string{
		"package/embedded.tar.gz",
		"package/hidden.zip",
		"package/bundle.tgz",
		"package/payload.7z",
		"package/archive.rar",
		"package/wheel.whl",
		"package/lib.jar",
	}

	for _, target := range nestedPayloads {
		t.Run(target, func(t *testing.T) {
			tarball := createTestTarball(t, map[string][]byte{
				"package/package.json": []byte(`{"name":"nested-test"}`),
				target:                 []byte("PK\x03\x04fake-archive-bytes"),
			}, nil)

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected ErrArchiveNestedArchive for %s, got nil", target)
			}
			if !errors.Is(err, ErrArchiveNestedArchive) {
				t.Fatalf("expected ErrArchiveNestedArchive, got: %v", err)
			}
		})
	}
}

// TestArchiveAdversarial_NoCodeExecutionDuringInspection asserts that no package code
// is executed during archive inspection, using both static AST inspection and dynamic verification.
func TestArchiveAdversarial_NoCodeExecutionDuringInspection(t *testing.T) {
	tempDir := t.TempDir()
	canaryFile := filepath.Join(tempDir, "adversarial_executed.marker")

	// Dynamic test: craft a package with postinstall, preinstall, install, binding.gyp, index.js
	// containing shell commands and script executions that write to canaryFile if executed.
	pkgJSON, err := json.Marshal(map[string]interface{}{
		"name":    "adversarial-exec-test",
		"version": "1.0.0",
		"scripts": map[string]string{
			"preinstall":  "touch " + canaryFile,
			"install":     "touch " + canaryFile,
			"postinstall": "touch " + canaryFile,
		},
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": pkgJSON,
		"package/index.js":     []byte("require('fs').writeFileSync('" + canaryFile + "', 'leak');\n"),
		"package/binding.gyp":  []byte(`{"targets": [{"target_name": "canary", "sources": ["touch ` + canaryFile + `"]}]}`),
	}, nil)

	limits := DefaultArchiveLimits()
	inspectLimits := DefaultInspectLimits()

	inspection, err := InspectArchiveWithLimits(context.Background(), bytes.NewReader(tarball), limits, inspectLimits, nil)
	if err != nil {
		t.Fatalf("InspectArchiveWithLimits failed: %v", err)
	}

	// 1. Dynamic proof: Assert canary marker was NEVER created
	if _, err := os.Stat(canaryFile); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY FAILURE: package code executed during inspection! %s exists", canaryFile)
	}

	// 2. Proof of detection: install scripts and native build were detected purely statically
	if !inspection.HasInstallScript {
		t.Error("expected HasInstallScript = true")
	}
	if !inspection.HasNativeBuild {
		t.Error("expected HasNativeBuild = true")
	}

	// 3. Static AST proof: verify that all Go files in internal/quarantine never import os/exec, plugin, or syscall
	fset := token.NewFileSet()
	quarantineDir := "."
	entries, err := os.ReadDir(quarantineDir)
	if err != nil {
		t.Fatalf("failed reading quarantine dir: %v", err)
	}

	prohibitedPkgs := map[string]bool{
		"os/exec": true,
		"plugin":  true,
		"syscall": true,
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(quarantineDir, entry.Name())
		node, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed parsing %s: %v", path, err)
		}
		for _, imp := range node.Imports {
			impPath := strings.Trim(imp.Path.Value, `"`)
			if prohibitedPkgs[impPath] || strings.HasPrefix(impPath, "golang.org/x/sys") {
				t.Fatalf("SECURITY VIOLATION: production code in %s imports prohibited package %q", entry.Name(), impPath)
			}
		}
	}
}
