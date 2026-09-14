package quarantine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"testing"
)

func createTestTarball(t *testing.T, files map[string][]byte, symlinks map[string]string) []byte {
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

	// Each field must be positive
	testCases := []struct {
		name   string
		mutate func(*ArchiveLimits)
	}{
		{"ZeroMaxTarballBytes", func(l *ArchiveLimits) { l.MaxTarballBytes = 0 }},
		{"ZeroMaxExtractedBytes", func(l *ArchiveLimits) { l.MaxExtractedBytes = 0 }},
		{"ZeroMaxEntryCount", func(l *ArchiveLimits) { l.MaxEntryCount = 0 }},
		{"ZeroMaxFileBytes", func(l *ArchiveLimits) { l.MaxFileBytes = 0 }},
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

func TestInspectArchive_PathTraversalBlocked(t *testing.T) {
	testCases := []struct {
		name      string
		entryPath string
	}{
		{"RelativeParent", "../../../etc/passwd"},
		{"SubdirParent", "package/../../etc/passwd"},
		{"AbsoluteUnix", "/etc/passwd"},
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

func TestInspectArchive_SymlinkEscapeBlocked(t *testing.T) {
	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"symlink-pkg"}`),
	}, map[string]string{
		"package/secret": "../../etc/shadow",
	})

	limits := DefaultArchiveLimits()
	_, err := InspectArchive(context.Background(), bytes.NewReader(tarball), limits)
	if err == nil {
		t.Fatal("expected error for escaping symlink, got nil")
	}
	if !errors.Is(err, ErrArchiveSymlinkEscape) {
		t.Errorf("expected ErrArchiveSymlinkEscape, got: %v", err)
	}
}

func TestInspectArchive_BombAndSizeLimits(t *testing.T) {
	t.Run("ExceedsEntryCount", func(t *testing.T) {
		files := make(map[string][]byte)
		for i := 0; i < 15; i++ {
			files[string(rune('a'+i))] = []byte("x")
		}
		tarball := createTestTarball(t, files, nil)

		limits := DefaultArchiveLimits()
		limits.MaxEntryCount = 10 // only allow 10 entries

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
}
