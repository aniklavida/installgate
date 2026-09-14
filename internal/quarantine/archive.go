package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

var (
	ErrArchiveTooLarge       = errors.New("archive inspection failed: compressed size exceeds limit")
	ErrArchiveBomb           = errors.New("archive inspection failed: uncompressed size exceeds limit (possible decompression bomb)")
	ErrArchiveTooManyEntries = errors.New("archive inspection failed: entry count exceeds limit")
	ErrArchiveEntryTooLarge  = errors.New("archive inspection failed: single entry size exceeds limit")
	ErrArchivePathTraversal  = errors.New("archive inspection failed: entry attempts path traversal")
	ErrArchiveSymlinkEscape  = errors.New("archive inspection failed: symlink escapes archive root")
	ErrArchiveTimeout        = errors.New("archive inspection failed: timeout exceeded")
)

// ArchiveLimits sets explicit and strict boundary constraints for inspecting tarballs.
// No implicit defaults are allowed; all fields must be explicitly set and validated.
type ArchiveLimits struct {
	MaxTarballBytes   int64         // Maximum compressed tarball size in bytes
	MaxExtractedBytes int64         // Maximum total uncompressed bytes across all entries
	MaxEntryCount     int           // Maximum total number of file entries
	MaxFileBytes      int64         // Maximum size of any single uncompressed entry
	Timeout           time.Duration // Maximum time allocated for archive inspection
}

// Validate ensures all required limits are explicitly set to positive values.
func (l ArchiveLimits) Validate() error {
	if l.MaxTarballBytes <= 0 {
		return errors.New("quarantine: explicit MaxTarballBytes greater than zero is required")
	}
	if l.MaxExtractedBytes <= 0 {
		return errors.New("quarantine: explicit MaxExtractedBytes greater than zero is required")
	}
	if l.MaxEntryCount <= 0 {
		return errors.New("quarantine: explicit MaxEntryCount greater than zero is required")
	}
	if l.MaxFileBytes <= 0 {
		return errors.New("quarantine: explicit MaxFileBytes greater than zero is required")
	}
	if l.Timeout <= 0 {
		return errors.New("quarantine: explicit Timeout greater than zero is required")
	}
	return nil
}

// DefaultArchiveLimits returns strict, explicit limits suitable for package tarball inspection.
func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxTarballBytes:   50 * 1024 * 1024,  // 50 MiB compressed
		MaxExtractedBytes: 250 * 1024 * 1024, // 250 MiB uncompressed
		MaxEntryCount:     10000,             // 10,000 files
		MaxFileBytes:      20 * 1024 * 1024,  // 20 MiB single file
		Timeout:           15 * time.Second,  // 15 seconds max inspection
	}
}

// ArchiveInspection summarizes safe static inspection findings of an archive.
// It never executes package contents and never stores or echoes file contents.
type ArchiveInspection struct {
	EntryCount          int
	TotalExtractedBytes int64
	HasInstallScript    bool
	InstallScripts      []string
	HasNativeBuild      bool
	Signals             []verdict.Signal
}

type packageJSONSummary struct {
	Scripts map[string]string `json:"scripts"`
	Gypfile bool              `json:"gypfile"`
}

// InspectArchive performs bounded, non-executing static inspection of a gzip-compressed tarball.
// It rigorously enforces path safety, bomb protection, and entry count limits.
func InspectArchive(ctx context.Context, r io.Reader, limits ArchiveLimits) (*ArchiveInspection, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}

	inspectCtx := ctx
	var cancel context.CancelFunc
	if limits.Timeout > 0 {
		inspectCtx, cancel = context.WithTimeout(ctx, limits.Timeout)
		defer cancel()
	}

	// 1. Bound compressed input
	limitReader := io.LimitReader(r, limits.MaxTarballBytes+1)

	gzReader, err := gzip.NewReader(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed creating gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	var entryCount int
	var totalExtracted int64
	var hasInstallScript bool
	var detectedScripts []string
	var hasNativeBuild bool

	now := time.Now().UTC().Truncate(time.Millisecond)

	for {
		if inspectCtx.Err() != nil {
			if errors.Is(inspectCtx.Err(), context.DeadlineExceeded) {
				return nil, ErrArchiveTimeout
			}
			return nil, inspectCtx.Err()
		}

		hdr, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("error reading tar entry: %w", err)
		}

		entryCount++
		if entryCount > limits.MaxEntryCount {
			return nil, ErrArchiveTooManyEntries
		}

		// 2. Validate path safety (prevent path traversal and directory traversal)
		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "/") || strings.HasPrefix(cleanName, "\\") || filepath.IsAbs(cleanName) {
			return nil, fmt.Errorf("%w: absolute path %q", ErrArchivePathTraversal, hdr.Name)
		}
		if cleanName == ".." || strings.HasPrefix(cleanName, "../") || strings.HasPrefix(cleanName, `..\`) {
			return nil, fmt.Errorf("%w: parent path %q", ErrArchivePathTraversal, hdr.Name)
		}

		// 3. Validate symlink destinations
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			cleanLink := filepath.Clean(hdr.Linkname)
			if strings.HasPrefix(cleanLink, "/") || strings.HasPrefix(cleanLink, "\\") || filepath.IsAbs(cleanLink) {
				return nil, fmt.Errorf("%w: absolute link target %q", ErrArchiveSymlinkEscape, hdr.Linkname)
			}
			if cleanLink == ".." || strings.HasPrefix(cleanLink, "../") || strings.HasPrefix(cleanLink, `..\`) {
				return nil, fmt.Errorf("%w: link escaping root %q", ErrArchiveSymlinkEscape, hdr.Linkname)
			}
		}

		// 4. Validate entry size against single file and cumulative bomb limits
		if hdr.Size > limits.MaxFileBytes {
			return nil, fmt.Errorf("%w: entry %q size %d exceeds limit %d",
				ErrArchiveEntryTooLarge, cleanName, hdr.Size, limits.MaxFileBytes)
		}

		totalExtracted += hdr.Size
		if totalExtracted > limits.MaxExtractedBytes {
			return nil, ErrArchiveBomb
		}

		// 5. Inspect static surface: check for native build artifacts
		baseName := filepath.Base(cleanName)
		if strings.EqualFold(baseName, "binding.gyp") || strings.HasSuffix(baseName, ".node") {
			hasNativeBuild = true
		}

		// 6. Inspect static surface: parse package.json for install scripts
		if isPackageJSON(cleanName) && hdr.Typeflag == tar.TypeReg {
			scripts, gyp, err := inspectPackageJSON(tarReader, hdr.Size, limits.MaxFileBytes)
			if err == nil {
				if len(scripts) > 0 {
					hasInstallScript = true
					detectedScripts = append(detectedScripts, scripts...)
				}
				if gyp {
					hasNativeBuild = true
				}
			}
		}
	}

	// Produce canonical evidence observations
	var signals []verdict.Signal
	freshUntil := now.Add(24 * time.Hour)

	if hasInstallScript {
		signals = append(signals, verdict.Signal{
			Kind:        evidence.KindInstallScript,
			Source:      "quarantine_archive",
			Observation: "present",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	} else if hasNativeBuild {
		signals = append(signals, verdict.Signal{
			Kind:        evidence.KindInstallScript,
			Source:      "quarantine_archive",
			Observation: "native_build",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	} else {
		signals = append(signals, verdict.Signal{
			Kind:        evidence.KindInstallScript,
			Source:      "quarantine_archive",
			Observation: "none",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	}

	return &ArchiveInspection{
		EntryCount:          entryCount,
		TotalExtractedBytes: totalExtracted,
		HasInstallScript:    hasInstallScript,
		InstallScripts:      detectedScripts,
		HasNativeBuild:      hasNativeBuild,
		Signals:             signals,
	}, nil
}

func isPackageJSON(path string) bool {
	clean := filepath.Clean(path)
	return clean == "package.json" ||
		clean == "package/package.json" ||
		strings.HasSuffix(clean, "/package.json")
}

var lifecycleScriptNames = map[string]bool{
	"preinstall":  true,
	"install":     true,
	"postinstall": true,
	"prepublish":  true,
	"preprepare":  true,
	"prepare":     true,
	"postprepare": true,
}

func inspectPackageJSON(r io.Reader, size, maxBytes int64) ([]string, bool, error) {
	limit := size
	if limit > maxBytes {
		limit = maxBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, false, err
	}

	var pkg packageJSONSummary
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, false, err
	}

	var found []string
	for scriptName := range pkg.Scripts {
		lower := strings.ToLower(strings.TrimSpace(scriptName))
		if lifecycleScriptNames[lower] {
			found = append(found, lower)
		}
	}

	return found, pkg.Gypfile, nil
}
