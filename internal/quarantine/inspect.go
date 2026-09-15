package quarantine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

// Named constants for explicit default static inspection limits.
const (
	DefaultMaxScriptBytes      int           = 4 * 1024         // 4 KiB per script value
	DefaultMaxScriptCount      int           = 10               // at most 10 lifecycle scripts examined
	DefaultMaxPackageJSONBytes int64         = 512 * 1024       // 512 KiB per package.json
	DefaultMaxFilesScanned     int           = 50               // 50 non-package.json files maximum
	DefaultMaxFileReadBytes    int64         = 64 * 1024        // 64 KiB per file
	DefaultInspectTimeout      time.Duration = 10 * time.Second // 10 s total budget
)

// InspectLimits defines explicit bounds for every axis of static inspection.
// Every field must be positive; Validate rejects zero or negative values.
type InspectLimits struct {
	// MaxScriptBytes is the maximum bytes read from any single lifecycle script value.
	MaxScriptBytes int

	// MaxScriptCount is the maximum number of lifecycle-script fields examined per package.json.
	MaxScriptCount int

	// MaxPackageJSONBytes is the maximum bytes consumed from any single package.json entry.
	MaxPackageJSONBytes int64

	// MaxFilesScanned is the maximum number of non-package.json JavaScript files
	// opened for indicator scanning. Files beyond this limit produce a degraded observation.
	MaxFilesScanned int

	// MaxFileReadBytes is the maximum bytes read from any single JavaScript file during scanning.
	MaxFileReadBytes int64

	// Timeout caps total wall-clock time for one InspectScripts call.
	Timeout time.Duration
}

// Validate rejects any InspectLimits that has an unset or non-positive field.
func (l InspectLimits) Validate() error {
	if l.MaxScriptBytes <= 0 {
		return errors.New("quarantine: explicit MaxScriptBytes greater than zero is required")
	}
	if l.MaxScriptCount <= 0 {
		return errors.New("quarantine: explicit MaxScriptCount greater than zero is required")
	}
	if l.MaxPackageJSONBytes <= 0 {
		return errors.New("quarantine: explicit MaxPackageJSONBytes greater than zero is required")
	}
	if l.MaxFilesScanned <= 0 {
		return errors.New("quarantine: explicit MaxFilesScanned greater than zero is required")
	}
	if l.MaxFileReadBytes <= 0 {
		return errors.New("quarantine: explicit MaxFileReadBytes greater than zero is required")
	}
	if l.Timeout <= 0 {
		return errors.New("quarantine: explicit Timeout greater than zero is required")
	}
	return nil
}

// DefaultInspectLimits returns strict, explicit limits for bounded static inspection.
func DefaultInspectLimits() InspectLimits {
	return InspectLimits{
		MaxScriptBytes:      DefaultMaxScriptBytes,
		MaxScriptCount:      DefaultMaxScriptCount,
		MaxPackageJSONBytes: DefaultMaxPackageJSONBytes,
		MaxFilesScanned:     DefaultMaxFilesScanned,
		MaxFileReadBytes:    DefaultMaxFileReadBytes,
		Timeout:             DefaultInspectTimeout,
	}
}

// ScriptInspection is the result of bounded static inspection of an npm tarball's install surface.
// Signals always carry source="quarantine_inspect". A degraded observation is emitted whenever
// any limit was reached during inspection; it never silently reads as all-clear.
type ScriptInspection struct {
	// Signals holds all observations produced, in evidence.Signal / verdict.Signal shape.
	Signals []verdict.Signal

	// Truncated is true when at least one inspection limit was reached.
	Truncated bool

	// HasInstallScript indicates whether any lifecycle script was found.
	HasInstallScript bool

	// InstallScripts lists the names of found lifecycle scripts.
	InstallScripts []string

	// HasNativeBuild indicates whether native build configuration was found.
	HasNativeBuild bool

	// DangerousScripts lists the names of scripts matching danger indicators.
	DangerousScripts []string

	// DangerousReasons lists the explanation for each dangerous script finding.
	DangerousReasons []string
}

// approvedLifecycleScripts lists exactly the script hooks that run at install time.
// This set is kept intentionally narrow; adding hooks here widens the attack surface.
var approvedLifecycleScripts = map[string]bool{
	"preinstall":  true,
	"install":     true,
	"postinstall": true,
	"prepare":     true,
}

// indicatorPatterns are compiled regular expressions for focused threat indicators.
// Each pattern targets a specific class of dangerous behaviour that could execute at
// install time without any package code running during inspection.
var indicatorPatterns = []indicatorRule{
	// Process execution — spawning shells or child processes
	{
		id:      "proc_exec",
		pattern: regexp.MustCompile(`(?i)\b(child_process|exec\s*\(|execSync\s*\(|spawn\s*\(|spawnSync\s*\(|execFile\s*\(|fork\s*\(|(ba)?sh\s+-c|powershell(\.exe)?|cmd(\.exe)?)\b|/(bin|usr/bin)/(ba)?sh`),
		obs:     "process_execution",
		conf:    evidence.ConfidenceHigh,
	},
	// Outbound network access — fetching remote resources at install time
	{
		id:      "net_fetch",
		pattern: regexp.MustCompile(`(?i)\b(https?:|node-fetch|axios|got\s*\(|request\s*\(|urllib|curl\s+|wget\s+|dns\.lookup|net\.connect|net\.Socket|tls\.connect|fetch\s*\()`),
		obs:     "network_access",
		conf:    evidence.ConfidenceMedium,
	},
	// Staged payload fetch — downloading and executing a remote payload
	{
		id:      "staged_payload",
		pattern: regexp.MustCompile(`(?i)(curl.*\|\s*(ba)?sh|wget.*\|\s*(ba)?sh|eval\s*\(.*fetch|download.*exec|pipe.*sh|base64.*decode.*eval|atob.*eval|base64\s+-d.*\|\s*(ba)?sh)`),
		obs:     "staged_payload",
		conf:    evidence.ConfidenceHigh,
	},
	// Credential and environment reads — accessing secrets from the environment
	{
		id:      "credential_read",
		pattern: regexp.MustCompile(`(?i)(\bprocess\.env\b|\.npmrc\b|\.netrc\b|\bkeychain\b|\bsecret_key\b|\bapi_key\b|\bid_rsa\b)`),
		obs:     "credential_read",
		conf:    evidence.ConfidenceMedium,
	},
	// Obfuscation — encoded or eval-based code hiding
	{
		id:      "obfuscation",
		pattern: regexp.MustCompile(`(?i)(\\x[0-9a-f]{2}){4,}|eval\s*\(|Function\s*\(\s*['"]|fromCharCode|unescape\s*\(|decodeURIComponent\s*\(.*eval|(\\u[0-9a-f]{4}){3,}`),
		obs:     "obfuscation",
		conf:    evidence.ConfidenceMedium,
	},
}

type indicatorRule struct {
	id      string
	pattern *regexp.Regexp
	obs     string
	conf    string
}

type packageJSONSummary struct {
	Scripts map[string]string `json:"scripts"`
	Gypfile bool              `json:"gypfile"`
}

type pkgInspectionResult struct {
	scripts          []string
	hasNativeBuild   bool
	dangerousScripts []string
	dangerousReasons []string
	signals          []verdict.Signal
}

// inspectPackageJSONContent extracts and inspects the approved surface within package.json.
func inspectPackageJSONContent(
	r io.Reader,
	size int64,
	limits InspectLimits,
	previousPkgJSON []byte,
	now, freshUntil time.Time,
) (pkgInspectionResult, bool, error) {
	var truncated bool
	readLimit := size
	if readLimit > limits.MaxPackageJSONBytes {
		readLimit = limits.MaxPackageJSONBytes
		truncated = true
	}

	data, err := io.ReadAll(io.LimitReader(r, readLimit))
	if err != nil {
		return pkgInspectionResult{}, truncated, err
	}

	var pkg packageJSONSummary
	if err := json.Unmarshal(data, &pkg); err != nil {
		return pkgInspectionResult{}, truncated, err
	}

	// Parse previous package.json if available
	var prevScripts map[string]string
	if len(previousPkgJSON) > 0 {
		var prev packageJSONSummary
		if err := json.Unmarshal(previousPkgJSON, &prev); err == nil {
			prevScripts = prev.Scripts
		}
	}

	var foundScripts []string
	var dangerousScripts []string
	var dangerousReasons []string
	var signals []verdict.Signal
	scriptCount := 0

	for name, cmd := range pkg.Scripts {
		lower := strings.ToLower(strings.TrimSpace(name))
		if !approvedLifecycleScripts[lower] {
			continue
		}

		if scriptCount >= limits.MaxScriptCount {
			truncated = true
			break
		}

		val := cmd
		if len(val) > limits.MaxScriptBytes {
			val = val[:limits.MaxScriptBytes]
			truncated = true
		}

		foundScripts = append(foundScripts, lower)
		scriptCount++

		isNew := false
		if prevScripts != nil {
			if _, hadBefore := prevScripts[lower]; !hadBefore {
				isNew = true
			}
		}

		if isNew {
			signals = append(signals, verdict.Signal{
				Kind:        evidence.KindInstallScript,
				Source:      "quarantine_inspect",
				Observation: fmt.Sprintf("new_lifecycle_script:%s", lower),
				Confidence:  evidence.ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
			signals = append(signals, verdict.Signal{
				Kind:        evidence.KindInstallScript,
				Source:      "quarantine_inspect",
				Observation: "script_added",
				Confidence:  evidence.ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}

		signals = append(signals, verdict.Signal{
			Kind:        evidence.KindInstallScript,
			Source:      "quarantine_inspect",
			Observation: fmt.Sprintf("lifecycle_script:%s", lower),
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})

		// Run focused indicator rules
		scriptDangerous := false
		for _, rule := range indicatorPatterns {
			if rule.pattern.MatchString(val) {
				scriptDangerous = true
				signals = append(signals, verdict.Signal{
					Kind:        evidence.KindInstallScript,
					Source:      "quarantine_inspect",
					Observation: fmt.Sprintf("indicator:%s:script:%s", rule.obs, lower),
					Confidence:  rule.conf,
					RetrievedAt: now,
					FreshUntil:  freshUntil,
				})
				dangerousReasons = append(dangerousReasons, fmt.Sprintf("%s indicator in %s", rule.obs, lower))
			}
		}

		if scriptDangerous {
			dangerousScripts = append(dangerousScripts, lower)
			signals = append(signals, verdict.Signal{
				Kind:        evidence.KindInstallScript,
				Source:      "quarantine_inspect",
				Observation: fmt.Sprintf("dangerous_script:%s", lower),
				Confidence:  evidence.ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}
	}

	return pkgInspectionResult{
		scripts:          foundScripts,
		hasNativeBuild:   pkg.Gypfile,
		dangerousScripts: dangerousScripts,
		dangerousReasons: dangerousReasons,
		signals:          signals,
	}, truncated, nil
}

// InspectScripts performs bounded static inspection of an npm tarball's install-time surface.
//
// Approved surfaces read:
//   - package.json: lifecycle scripts (preinstall, install, postinstall, prepare)
//   - package.json: implicit native build via gypfile/binding.gyp
//   - Scripts newly introduced relative to previousPkgJSON (nil means no previous version)
//   - Focused threat indicators within those script values
//
// Anything outside these surfaces is not read. This function never executes package
// code, never shells out, and never spawns a subprocess.
func InspectScripts(
	ctx context.Context,
	r io.Reader,
	archiveLimits ArchiveLimits,
	inspectLimits InspectLimits,
	previousPkgJSON []byte,
) (*ScriptInspection, error) {
	if err := archiveLimits.Validate(); err != nil {
		return nil, err
	}
	if err := inspectLimits.Validate(); err != nil {
		return nil, err
	}

	inspection, err := InspectArchiveWithLimits(ctx, r, archiveLimits, inspectLimits, previousPkgJSON)
	if err != nil {
		return nil, err
	}

	return &ScriptInspection{
		Signals:          inspection.Signals,
		Truncated:        inspection.Truncated,
		HasInstallScript: inspection.HasInstallScript,
		InstallScripts:   inspection.InstallScripts,
		HasNativeBuild:   inspection.HasNativeBuild,
		DangerousScripts: inspection.DangerousScripts,
		DangerousReasons: inspection.DangerousReasons,
	}, nil
}

// ScriptInspectionFromArchive is a convenience wrapper that runs InspectScripts over
// the bytes of an already-buffered tarball (e.g. from the quarantine blobstore).
func ScriptInspectionFromArchive(
	ctx context.Context,
	tarball []byte,
	archiveLimits ArchiveLimits,
	inspectLimits InspectLimits,
	previousPkgJSON []byte,
) (*ScriptInspection, error) {
	return InspectScripts(ctx, bytes.NewReader(tarball), archiveLimits, inspectLimits, previousPkgJSON)
}
