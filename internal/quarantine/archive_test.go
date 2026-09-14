package quarantine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func createTestTarball(t *testing.T, files map[string][]byte, symlinks map[string]string) []byte {
	t.Helper()
	return createCustomTarball(t, files, symlinks, nil, nil)
}

func createCustomTarball(t *testing.T, files map[string][]byte, symlinks map[string]string, hardlinks map[string]string, duplicates []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed writing tar header for %s: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("failed writing tar content for %s: %v", name, err)
		}
	}

	for name, target := range symlinks {
		hdr := &tar.Header{
			Name:     name,
			Linkname: target,
			Typeflag: tar.TypeSymlink,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed writing tar symlink header for %s: %v", name, err)
		}
	}

	for name, target := range hardlinks {
		hdr := &tar.Header{
			Name:     name,
			Linkname: target,
			Typeflag: tar.TypeLink,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed writing tar hardlink header for %s: %v", name, err)
		}
	}

	for _, name := range duplicates {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len("duplicate")),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed writing duplicate tar header for %s: %v", name, err)
		}
		if _, err := tw.Write([]byte("duplicate")); err != nil {
			t.Fatalf("failed writing duplicate tar content for %s: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("failed closing tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed closing gzip writer: %v", err)
	}

	return buf.Bytes()
}

func TestArchiveLimits_Validation(t *testing.T) {
	valid := DefaultArchiveLimits()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid limits failed validation: %v", err)
	}

	testCases := []struct {
		name   string
		mutate func(*ArchiveLimits)
	}{
		{"ZeroMaxTarballBytes", func(l *ArchiveLimits) { l.MaxTarballBytes = 0 }},
		{"ZeroMaxExtractedBytes", func(l *ArchiveLimits) { l.MaxExtractedBytes = 0 }},
		{"ZeroMaxEntryCount", func(l *ArchiveLimits) { l.MaxEntryCount = 0 }},
		{"ZeroMaxFileBytes", func(l *ArchiveLimits) { l.MaxFileBytes = 0 }},
		{"ZeroMaxNestingDepth", func(l *ArchiveLimits) { l.MaxNestingDepth = 0 }},
		{"ZeroTimeout", func(l *ArchiveLimits) { l.Timeout = 0 }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			limits := DefaultArchiveLimits()
			tc.mutate(&limits)
			if err := limits.Validate(); err == nil {
				t.Errorf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}

func TestArchiveLimits_NamedConstants(t *testing.T) {
	limits := DefaultArchiveLimits()
	if limits.MaxTarballBytes != DefaultMaxTarballBytes {
		t.Errorf("MaxTarballBytes = %d, want %d", limits.MaxTarballBytes, DefaultMaxTarballBytes)
	}
	if limits.MaxExtractedBytes != DefaultMaxExtractedBytes {
		t.Errorf("MaxExtractedBytes = %d, want %d", limits.MaxExtractedBytes, DefaultMaxExtractedBytes)
	}
	if limits.MaxEntryCount != DefaultMaxEntryCount {
		t.Errorf("MaxEntryCount = %d, want %d", limits.MaxEntryCount, DefaultMaxEntryCount)
	}
	if limits.MaxFileBytes != DefaultMaxFileBytes {
		t.Errorf("MaxFileBytes = %d, want %d", limits.MaxFileBytes, DefaultMaxFileBytes)
	}
	if limits.MaxNestingDepth != DefaultMaxNestingDepth {
		t.Errorf("MaxNestingDepth = %d, want %d", limits.MaxNestingDepth, DefaultMaxNestingDepth)
	}
	if limits.Timeout != DefaultArchiveTimeout {
		t.Errorf("Timeout = %v, want %v", limits.Timeout, DefaultArchiveTimeout)
	}
}

func TestInspectArchive_DetectsInstallScript(t *testing.T) {
	pkgJSON := []byte(`{
		"name": "with-scripts",
		"version": "1.0.0",
		"scripts": {
			"postinstall": "node setup.js"
		}
	}`)

	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": pkgJSON,
		"package/index.js":     []byte("module.exports = 42;\n"),
	}, nil)

	limits := DefaultArchiveLimits()
	inspection, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
	if err != nil {
		t.Fatalf("InspectArchive failed: %v", err)
	}

	if !inspection.HasInstallScript {
		t.Error("expected HasInstallScript = true")
	}
	if len(inspection.InstallScripts) != 1 || inspection.InstallScripts[0] != "postinstall" {
		t.Errorf("expected postinstall script, got: %v", inspection.InstallScripts)
	}
	if inspection.EntryCount != 2 {
		t.Errorf("EntryCount = %d, want 2", inspection.EntryCount)
	}
}

func TestInspectArchive_DetectsNativeBuild(t *testing.T) {
	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"native-pkg","version":"1.0.0"}`),
		"package/binding.gyp":  []byte(`{ "targets": [] }`),
	}, nil)

	limits := DefaultArchiveLimits()
	inspection, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
	if err != nil {
		t.Fatalf("InspectArchive failed: %v", err)
	}

	if !inspection.HasNativeBuild {
		t.Error("expected HasNativeBuild = true")
	}
}

// 1. Path Traversal fixture fails closed.
func TestInspectArchive_PathTraversalBlocked(t *testing.T) {
	testCases := []struct {
		name      string
		entryPath string
	}{
		{"RelativeParent", "../../../etc/passwd"},
		{"SubdirParent", "package/../../etc/passwd"},
		{"AbsoluteUnix", "/etc/passwd"},
		{"WindowsBackslashTraversal", "..\\..\\etc\\passwd"},
		{"WindowsSubdirBackslash", "package\\..\\..\\etc\\passwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tarball := createTestTarball(t, map[string][]byte{
				tc.entryPath: []byte("malicious file"),
			}, nil)

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected error for path traversal %q, got nil", tc.entryPath)
			}
			if !errors.Is(err, ErrArchivePathTraversal) {
				t.Errorf("expected ErrArchivePathTraversal, got: %v", err)
			}
		})
	}
}

// 2. Symlink Escape fixture fails closed.
func TestInspectArchive_SymlinkEscapeBlocked(t *testing.T) {
	testCases := []struct {
		name   string
		source string
		target string
	}{
		{"EscapingParent", "package/secret", "../../etc/shadow"},
		{"AbsoluteTarget", "package/secret", "/etc/shadow"},
		{"DeepRelativeEscape", "package/a/b/c", "../../../../etc/passwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tarball := createTestTarball(t, map[string][]byte{
				"package/package.json": []byte(`{"name":"symlink-pkg"}`),
			}, map[string]string{
				tc.source: tc.target,
			})

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected error for escaping symlink %s -> %s, got nil", tc.source, tc.target)
			}
			if !errors.Is(err, ErrArchiveSymlinkEscape) {
				t.Errorf("expected ErrArchiveSymlinkEscape, got: %v", err)
			}
		})
	}
}

// 3. Hardlink Escape fixture fails closed.
func TestInspectArchive_HardlinkEscapeBlocked(t *testing.T) {
	testCases := []struct {
		name   string
		source string
		target string
	}{
		{"EscapingParent", "package/hardlink", "../../etc/shadow"},
		{"AbsoluteTarget", "package/hardlink", "/etc/shadow"},
		{"DeepRelativeEscape", "package/sub/hardlink", "../../../etc/passwd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tarball := createCustomTarball(t, map[string][]byte{
				"package/package.json": []byte(`{"name":"hardlink-pkg"}`),
			}, nil, map[string]string{
				tc.source: tc.target,
			}, nil)

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected error for escaping hardlink %s -> %s, got nil", tc.source, tc.target)
			}
			if !errors.Is(err, ErrArchiveHardlinkEscape) {
				t.Errorf("expected ErrArchiveHardlinkEscape, got: %v", err)
			}
		})
	}
}

// 4. Archive Bomb and 5. Entry Count and 6. Entry Size fixtures fail closed.
func TestInspectArchive_BombAndSizeLimits(t *testing.T) {
	t.Run("ExceedsEntryCount", func(t *testing.T) {
		files := make(map[string][]byte)
		for i := 0; i < 15; i++ {
			files[string(rune('a'+i))] = []byte("x")
		}
		tarball := createTestTarball(t, files, nil)

		limits := DefaultArchiveLimits()
		limits.MaxEntryCount = 10

		_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
		if err == nil {
			t.Fatal("expected ErrArchiveTooManyEntries, got nil")
		}
		if !errors.Is(err, ErrArchiveTooManyEntries) {
			t.Errorf("expected ErrArchiveTooManyEntries, got: %v", err)
		}
	})

	t.Run("ExceedsSingleFileSize", func(t *testing.T) {
		tarball := createTestTarball(t, map[string][]byte{
			"large.bin": bytes.Repeat([]byte("X"), 1000),
		}, nil)

		limits := DefaultArchiveLimits()
		limits.MaxFileBytes = 500

		_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
		if err == nil {
			t.Fatal("expected ErrArchiveEntryTooLarge, got nil")
		}
		if !errors.Is(err, ErrArchiveEntryTooLarge) {
			t.Errorf("expected ErrArchiveEntryTooLarge, got: %v", err)
		}
	})

	t.Run("ExceedsCumulativeBombLimit", func(t *testing.T) {
		tarball := createTestTarball(t, map[string][]byte{
			"f1.bin": bytes.Repeat([]byte("A"), 400),
			"f2.bin": bytes.Repeat([]byte("B"), 400),
			"f3.bin": bytes.Repeat([]byte("C"), 400),
		}, nil)

		limits := DefaultArchiveLimits()
		limits.MaxExtractedBytes = 1000

		_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
		if err == nil {
			t.Fatal("expected ErrArchiveBomb, got nil")
		}
		if !errors.Is(err, ErrArchiveBomb) {
			t.Errorf("expected ErrArchiveBomb, got: %v", err)
		}
	})

	t.Run("ExceedsCompressedTarballBytes", func(t *testing.T) {
		uncompressible := make([]byte, 1000)
		for i := range uncompressible {
			uncompressible[i] = byte(i*37 + 13)
		}
		tarball := createTestTarball(t, map[string][]byte{
			"data.bin": uncompressible,
		}, nil)

		limits := DefaultArchiveLimits()
		limits.MaxTarballBytes = 100 // compressed size will exceed 100 bytes

		_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
		if err == nil {
			t.Fatal("expected ErrArchiveTooLarge, got nil")
		}
		if !errors.Is(err, ErrArchiveTooLarge) {
			t.Errorf("expected ErrArchiveTooLarge, got: %v", err)
		}
	})
}

// 7. Duplicate Entry fixture fails closed.
func TestInspectArchive_DuplicateEntryBlocked(t *testing.T) {
	tarball := createCustomTarball(t, map[string][]byte{
		"package/index.js": []byte("console.log('original');\n"),
	}, nil, nil, []string{"package/index.js"})

	limits := DefaultArchiveLimits()
	_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
	if err == nil {
		t.Fatal("expected ErrArchiveDuplicateEntry, got nil")
	}
	if !errors.Is(err, ErrArchiveDuplicateEntry) {
		t.Errorf("expected ErrArchiveDuplicateEntry, got: %v", err)
	}
}

// 8. Nesting Depth fixture fails closed.
func TestInspectArchive_NestingDepthBlocked(t *testing.T) {
	deepPath := "package/" + strings.Repeat("sub/", 25) + "index.js"
	tarball := createTestTarball(t, map[string][]byte{
		deepPath: []byte("module.exports = {};\n"),
	}, nil)

	limits := DefaultArchiveLimits()
	limits.MaxNestingDepth = 10

	_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
	if err == nil {
		t.Fatal("expected ErrArchiveDepthExceeded, got nil")
	}
	if !errors.Is(err, ErrArchiveDepthExceeded) {
		t.Errorf("expected ErrArchiveDepthExceeded, got: %v", err)
	}
}

// Nested archive fixture fails closed.
func TestInspectArchive_NestedArchiveBlocked(t *testing.T) {
	nestedFormats := []string{
		"package/embedded.zip",
		"package/inner.tar.gz",
		"package/payload.tgz",
		"package/data.7z",
	}

	for _, format := range nestedFormats {
		t.Run(format, func(t *testing.T) {
			tarball := createTestTarball(t, map[string][]byte{
				"package/package.json": []byte(`{"name":"nested-pkg"}`),
				format:                 []byte("fake-nested-archive-bytes"),
			}, nil)

			limits := DefaultArchiveLimits()
			_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
			if err == nil {
				t.Fatalf("expected ErrArchiveNestedArchive for %s, got nil", format)
			}
			if !errors.Is(err, ErrArchiveNestedArchive) {
				t.Errorf("expected ErrArchiveNestedArchive, got: %v", err)
			}
		})
	}
}

// 9. Timeout fixture fails closed.
func TestInspectArchive_TimeoutBlocked(t *testing.T) {
	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"timeout-pkg"}`),
		"package/index.js":     []byte("module.exports = 1;\n"),
	}, nil)

	limits := DefaultArchiveLimits()
	// Already expired context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, err := InspectArchive(ctx, bytes.NewReader(tarball), limits)
	if err == nil {
		t.Fatal("expected ErrArchiveTimeout on expired context, got nil")
	}
	if !errors.Is(err, ErrArchiveTimeout) {
		t.Errorf("expected ErrArchiveTimeout, got: %v", err)
	}
}
