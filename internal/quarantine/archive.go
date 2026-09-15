package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
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
	ErrArchiveHardlinkEscape = errors.New("archive inspection failed: hardlink escapes archive root")
	ErrArchiveDuplicateEntry = errors.New("archive inspection failed: duplicate entry path detected")
	ErrArchiveNestedArchive  = errors.New("archive inspection failed: nested archive entry detected")
	ErrArchiveDepthExceeded  = errors.New("archive inspection failed: entry nesting depth exceeds limit")
	ErrArchiveTimeout        = errors.New("archive inspection failed: timeout exceeded")
)

// Named constants for explicit default archive inspection limits.
const (
	DefaultMaxTarballBytes   int64         = 50 * 1024 * 1024  // 50 MiB compressed
	DefaultMaxExtractedBytes int64         = 250 * 1024 * 1024 // 250 MiB uncompressed
	DefaultMaxEntryCount     int           = 10000             // 10,000 files
	DefaultMaxFileBytes      int64         = 20 * 1024 * 1024  // 20 MiB single file
	DefaultMaxNestingDepth   int           = 20                // 20 path components deep
	DefaultArchiveTimeout    time.Duration = 15 * time.Second  // 15 seconds max inspection
)

// ArchiveLimits sets explicit and strict boundary constraints for inspecting tarballs.
// No implicit defaults are allowed; all fields must be explicitly set and validated.
type ArchiveLimits struct {
	MaxTarballBytes   int64         // Maximum compressed tarball size in bytes
	MaxExtractedBytes int64         // Maximum total uncompressed bytes across all entries
	MaxEntryCount     int           // Maximum total number of file entries
	MaxFileBytes      int64         // Maximum size of any single uncompressed entry
	MaxNestingDepth   int           // Maximum path component depth for any single entry
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
	if l.MaxNestingDepth <= 0 {
		return errors.New("quarantine: explicit MaxNestingDepth greater than zero is required")
	}
	if l.Timeout <= 0 {
		return errors.New("quarantine: explicit Timeout greater than zero is required")
	}
	return nil
}

// DefaultArchiveLimits returns strict, explicit limits suitable for package tarball inspection.
func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxTarballBytes:   DefaultMaxTarballBytes,
		MaxExtractedBytes: DefaultMaxExtractedBytes,
		MaxEntryCount:     DefaultMaxEntryCount,
		MaxFileBytes:      DefaultMaxFileBytes,
		MaxNestingDepth:   DefaultMaxNestingDepth,
		Timeout:           DefaultArchiveTimeout,
	}
}

// nestedArchiveExtensions lists extensions that indicate a nested archive inside a tarball.
// Nested archives bypass all per-entry limits when extracted by a naive installer.
var nestedArchiveExtensions = []string{
	".tar",
	".tar.gz",
	".tgz",
	".gz",
	".zip",
	".bz2",
	".tar.bz2",
	".tbz",
	".tbz2",
	".xz",
	".tar.xz",
	".txz",
	".7z",
	".rar",
	".whl",
	".egg",
	".gem",
	".nupkg",
	".jar",
	".war",
	".zst",
	".tar.zst",
}

// isNestedArchive reports whether a filename is a known nested-archive format.
func isNestedArchive(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range nestedArchiveExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// pathDepth counts the number of path components in a cleaned slash-separated path.
func pathDepth(cleanName string) int {
	if cleanName == "" || cleanName == "." {
		return 0
	}
	parts := strings.Split(cleanName, "/")
	count := 0
	for _, p := range parts {
		if p != "" && p != "." {
			count++
		}
	}
	return count
}

// ArchiveInspection summarizes safe static inspection findings of an archive.
// It never executes package contents and never stores or echoes file contents.
type ArchiveInspection struct {
	EntryCount          int
	TotalExtractedBytes int64
	HasInstallScript    bool
	InstallScripts      []string
	HasNativeBuild      bool
	DangerousScripts    []string
	DangerousReasons    []string
	Truncated           bool
	Signals             []verdict.Signal
}

type boundCountReader struct {
	ctx   context.Context
	r     io.Reader
	limit int64
	read  int64
}

func (b *boundCountReader) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, ErrArchiveTimeout
		}
		return 0, err
	}
	if b.read > b.limit {
		return 0, ErrArchiveTooLarge
	}
	n, err := b.r.Read(p)
	b.read += int64(n)
	if b.read > b.limit {
		return n, ErrArchiveTooLarge
	}
	if err != nil && b.ctx.Err() != nil {
		if errors.Is(b.ctx.Err(), context.DeadlineExceeded) {
			return n, ErrArchiveTimeout
		}
		return n, b.ctx.Err()
	}
	return n, err
}

// InspectArchive performs bounded, non-executing static inspection of a gzip-compressed tarball
// using default static inspection limits and without previous version diffing.
func InspectArchive(ctx context.Context, r io.Reader, limits ArchiveLimits) (*ArchiveInspection, error) {
	return InspectArchiveWithLimits(ctx, r, limits, DefaultInspectLimits(), nil)
}

// InspectArchiveWithLimits performs bounded, non-executing static inspection of a gzip-compressed tarball.
// It rigorously enforces path safety, bomb protection, entry count limits, hardlink escape,
// duplicate entries, nested archive detection, and nesting depth, and inspects approved static surfaces.
func InspectArchiveWithLimits(
	ctx context.Context,
	r io.Reader,
	archiveLimits ArchiveLimits,
	inspectLimits InspectLimits,
	previousPkgJSON []byte,
) (*ArchiveInspection, error) {
	if err := archiveLimits.Validate(); err != nil {
		return nil, err
	}
	if err := inspectLimits.Validate(); err != nil {
		return nil, err
	}

	inspectCtx := ctx
	var cancel context.CancelFunc
	if archiveLimits.Timeout > 0 {
		inspectCtx, cancel = context.WithTimeout(ctx, archiveLimits.Timeout)
		defer cancel()
	}

	cr := &boundCountReader{
		ctx:   inspectCtx,
		r:     r,
		limit: archiveLimits.MaxTarballBytes,
	}

	gzReader, err := gzip.NewReader(cr)
	if err != nil {
		if errors.Is(err, ErrArchiveTooLarge) || errors.Is(err, ErrArchiveTimeout) {
			return nil, err
		}
		if inspectCtx.Err() != nil && errors.Is(inspectCtx.Err(), context.DeadlineExceeded) {
			return nil, ErrArchiveTimeout
		}
		return nil, fmt.Errorf("failed creating gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	var entryCount int
	var totalExtracted int64
	var hasInstallScript bool
	var detectedScripts []string
	var hasNativeBuild bool
	var dangerousScripts []string
	var dangerousReasons []string
	var signals []verdict.Signal
	var truncated bool

	seenPaths := make(map[string]bool)
	now := time.Now().UTC().Truncate(time.Millisecond)
	freshUntil := now.Add(24 * time.Hour)

	var pkgJSONFound bool

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
			if errors.Is(err, ErrArchiveTimeout) || (inspectCtx.Err() != nil && errors.Is(inspectCtx.Err(), context.DeadlineExceeded)) {
				return nil, ErrArchiveTimeout
			}
			if errors.Is(err, ErrArchiveTooLarge) {
				return nil, ErrArchiveTooLarge
			}
			return nil, fmt.Errorf("error reading tar entry: %w", err)
		}

		entryCount++
		if entryCount > archiveLimits.MaxEntryCount {
			return nil, ErrArchiveTooManyEntries
		}

		// 1. Validate path safety (prevent path traversal)
		normalizedName := strings.ReplaceAll(hdr.Name, "\\", "/")
		cleanName := path.Clean(normalizedName)
		if strings.HasPrefix(cleanName, "/") || filepath.IsAbs(hdr.Name) || (len(cleanName) >= 2 && cleanName[1] == ':') {
			return nil, fmt.Errorf("%w: absolute path %q", ErrArchivePathTraversal, hdr.Name)
		}
		if cleanName == ".." || strings.HasPrefix(cleanName, "../") {
			return nil, fmt.Errorf("%w: parent path %q", ErrArchivePathTraversal, hdr.Name)
		}

		// 2. Check nesting depth
		depth := pathDepth(cleanName)
		if depth > archiveLimits.MaxNestingDepth {
			return nil, fmt.Errorf("%w: path %q has depth %d, limit %d",
				ErrArchiveDepthExceeded, cleanName, depth, archiveLimits.MaxNestingDepth)
		}

		// 3. Detect duplicate entries
		if seenPaths[cleanName] {
			return nil, fmt.Errorf("%w: %q", ErrArchiveDuplicateEntry, cleanName)
		}
		seenPaths[cleanName] = true

		// 4. Validate symlink destinations
		if hdr.Typeflag == tar.TypeSymlink {
			normalizedLink := strings.ReplaceAll(hdr.Linkname, "\\", "/")
			cleanLink := path.Clean(normalizedLink)
			if strings.HasPrefix(cleanLink, "/") || filepath.IsAbs(hdr.Linkname) || (len(cleanLink) >= 2 && cleanLink[1] == ':') {
				return nil, fmt.Errorf("%w: absolute link target %q", ErrArchiveSymlinkEscape, hdr.Linkname)
			}
			resolved := path.Clean(path.Join(path.Dir(cleanName), cleanLink))
			if cleanLink == ".." || strings.HasPrefix(cleanLink, "../") || resolved == ".." || strings.HasPrefix(resolved, "../") {
				return nil, fmt.Errorf("%w: link escaping root %q", ErrArchiveSymlinkEscape, hdr.Linkname)
			}
		}

		// 5. Validate hardlink destinations
		if hdr.Typeflag == tar.TypeLink {
			normalizedLink := strings.ReplaceAll(hdr.Linkname, "\\", "/")
			cleanLink := path.Clean(normalizedLink)
			if strings.HasPrefix(cleanLink, "/") || filepath.IsAbs(hdr.Linkname) || (len(cleanLink) >= 2 && cleanLink[1] == ':') {
				return nil, fmt.Errorf("%w: absolute hardlink target %q", ErrArchiveHardlinkEscape, hdr.Linkname)
			}
			resolved := path.Clean(path.Join(path.Dir(cleanName), cleanLink))
			if cleanLink == ".." || strings.HasPrefix(cleanLink, "../") || resolved == ".." || strings.HasPrefix(resolved, "../") {
				return nil, fmt.Errorf("%w: hardlink escaping root %q", ErrArchiveHardlinkEscape, hdr.Linkname)
			}
		}

		// 6. Validate entry size against single file and cumulative bomb limits
		if hdr.Size > archiveLimits.MaxFileBytes {
			return nil, fmt.Errorf("%w: entry %q size %d exceeds limit %d",
				ErrArchiveEntryTooLarge, cleanName, hdr.Size, archiveLimits.MaxFileBytes)
		}

		totalExtracted += hdr.Size
		if totalExtracted > archiveLimits.MaxExtractedBytes {
			return nil, ErrArchiveBomb
		}

		// 7. Block nested archives
		baseName := path.Base(cleanName)
		if hdr.Typeflag == tar.TypeReg && isNestedArchive(baseName) {
			return nil, fmt.Errorf("%w: %q", ErrArchiveNestedArchive, cleanName)
		}

		// 8. Inspect static surface: check for native build artifacts
		if strings.EqualFold(baseName, "binding.gyp") || strings.HasSuffix(baseName, ".node") {
			hasNativeBuild = true
		}

		// 9. Inspect static surface: parse package.json for lifecycle scripts and indicators
		if isPackageJSON(cleanName) && hdr.Typeflag == tar.TypeReg && !pkgJSONFound {
			pkgJSONFound = true
			res, pkgTrunc, err := inspectPackageJSONContent(tarReader, hdr.Size, inspectLimits, previousPkgJSON, now, freshUntil)
			if pkgTrunc {
				truncated = true
			}
			if err == nil {
				if len(res.scripts) > 0 {
					hasInstallScript = true
					detectedScripts = append(detectedScripts, res.scripts...)
				}
				if res.hasNativeBuild {
					hasNativeBuild = true
				}
				if len(res.dangerousScripts) > 0 {
					dangerousScripts = append(dangerousScripts, res.dangerousScripts...)
					dangerousReasons = append(dangerousReasons, res.dangerousReasons...)
				}
				signals = append(signals, res.signals...)
			}
		}
	}

	if cr.read > archiveLimits.MaxTarballBytes {
		return nil, ErrArchiveTooLarge
	}

	// Finalize signals
	if hasNativeBuild {
		signals = append(signals, verdict.Signal{
			Kind:        evidence.KindInstallScript,
			Source:      "quarantine_inspect",
			Observation: "native_build",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	}

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
		if !truncated {
			signals = append(signals, verdict.Signal{
				Kind:        evidence.KindInstallScript,
				Source:      "quarantine_inspect",
				Observation: "no_lifecycle_scripts",
				Confidence:  evidence.ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}
	}

	if truncated {
		signals = append(signals, verdict.Signal{
			Kind:        evidence.KindInstallScript,
			Source:      "quarantine_inspect",
			Observation: "inspect_truncated",
			Confidence:  evidence.ConfidenceNone,
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
		DangerousScripts:    dangerousScripts,
		DangerousReasons:    dangerousReasons,
		Truncated:           truncated,
		Signals:             signals,
	}, nil
}

func isPackageJSON(p string) bool {
	normalized := strings.ReplaceAll(p, "\\", "/")
	clean := path.Clean(normalized)
	return clean == "package.json" ||
		clean == "package/package.json" ||
		strings.HasSuffix(clean, "/package.json")
}
