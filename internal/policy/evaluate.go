package policy

import (
	"fmt"
	"strings"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

type Profile string

const (
	Balanced Profile = "balanced"
	Strict   Profile = "strict"
)

type Assessment struct {
	IntegrityMismatch             bool
	KnownMalicious                bool
	VulnerabilityAboveThreshold   bool
	StrongNameConfusion           bool
	NewbornOrFresh                bool
	PublisherOrProvenanceChanged  bool
	InstallScriptAdded            bool
	HasInstallScriptOrNativeBuild bool
	EvidenceUnavailable           bool
	FreshCachedAllow              bool
	LowPopularity                 bool
	MissingRepository             bool
	PackageNotFound               bool
	ConfusedWith                  string
	DangerousInstallScript        bool
	DangerousScriptNames          []string
	DangerousScriptReasons        []string
	InspectionTruncated           bool
}

// Evaluate applies the deterministic decision matrix according to the chosen profile.
// Strict profile is never more permissive than balanced profile for any input state.
func Evaluate(profile Profile, a Assessment) verdict.Decision {
	degraded := a.InspectionTruncated

	if a.PackageNotFound {
		return decision(verdict.Block, "registry.package-not-found", "package or version does not exist in the registry", degraded, "publish_history")
	}

	// Row 1: Integrity mismatch, or a known malicious package or version - block, block.
	if a.IntegrityMismatch || a.KnownMalicious {
		return decision(verdict.Block, "core.integrity-or-malicious", "integrity mismatch or known malicious evidence", degraded, "integrity", "malicious")
	}

	// Dangerous install script detected during static inspection - block, block.
	if a.DangerousInstallScript {
		scriptName := "lifecycle script"
		if len(a.DangerousScriptNames) > 0 {
			scriptName = strings.Join(uniqueStrings(a.DangerousScriptNames), ", ")
		}
		summary := fmt.Sprintf("dangerous install script detected in %s", scriptName)
		if len(a.DangerousScriptReasons) > 0 {
			summary = fmt.Sprintf("dangerous install script detected in %s: %s", scriptName, strings.Join(uniqueStrings(a.DangerousScriptReasons), "; "))
		}
		return decision(verdict.Block, "execution.dangerous-install-script", summary, degraded, "install_script")
	}

	// Row 2: Vulnerability above the configured severity threshold - block, block.
	if a.VulnerabilityAboveThreshold {
		return decision(verdict.Block, "core.vulnerability-threshold", "vulnerability exceeds the configured threshold", degraded, "vulnerability")
	}

	// Row 3: Strong name confusion corroborated by a newborn or fresh package - approval required, block.
	if a.StrongNameConfusion && a.NewbornOrFresh {
		summary := "a strongly confusing package name is corroborated by package freshness"
		if a.ConfusedWith != "" {
			summary = fmt.Sprintf("a strongly confusing package name is corroborated by package freshness: confusable with target %q", a.ConfusedWith)
		}
		if profile == Strict {
			return decision(verdict.Block, "identity.confusable-new", summary, degraded, "name_confusion", "package_age")
		}
		return decision(verdict.ApprovalRequired, "identity.confusable-new", summary, degraded, "name_confusion", "package_age")
	}

	// Row 4: Publisher or provenance change combined with a newly introduced install script - approval required, block.
	if a.PublisherOrProvenanceChanged && a.InstallScriptAdded {
		if profile == Strict {
			return decision(verdict.Block, "release.provenance-script-change", "publisher or provenance changed when an install script was added", degraded, "provenance", "install_script")
		}
		return decision(verdict.ApprovalRequired, "release.provenance-script-change", "publisher or provenance changed when an install script was added", degraded, "provenance", "install_script")
	}

	// Row 5: Install script or implicit native build with no corroborating risk - warn and audit, approval required.
	// Applies when evidence is available; evidence outages are governed by rows 6 and 7.
	if a.HasInstallScriptOrNativeBuild && !a.EvidenceUnavailable {
		if profile == Strict {
			return decision(verdict.ApprovalRequired, "execution.install-time", "the package can execute install-time code", degraded, "install_script")
		}
		return decision(verdict.Warn, "execution.install-time", "the package can execute install-time code", degraded, "install_script")
	}

	// Row 6: Evidence provider unavailable with a fresh cached allow - allow with a stale-evidence warning, approval required.
	if a.EvidenceUnavailable && a.FreshCachedAllow {
		if profile == Strict {
			return decision(verdict.ApprovalRequired, "availability.fresh-cache", "live evidence is unavailable; a fresh cached allow requires approval under the strict profile", true, "availability", "cache")
		}
		return decision(verdict.Allow, "availability.fresh-cache", "live evidence is unavailable; a fresh cached allow remains usable with a stale-evidence warning", true, "availability", "cache")
	}

	// Row 7: Evidence provider unavailable with no usable cache - approval required, block.
	if a.EvidenceUnavailable {
		if profile == Strict {
			return decision(verdict.Block, "availability.strict", "required evidence is unavailable under the strict profile", true, "availability")
		}
		return decision(verdict.ApprovalRequired, "availability.no-cache", "required evidence is unavailable and no usable cached allow exists", true, "availability")
	}

	// Row 8: Low popularity or missing repository alone - informational, warn.
	if a.LowPopularity || a.MissingRepository {
		if profile == Strict {
			return decision(verdict.Warn, "reputation.weak-signal", "weak reputation evidence is informational and not proof of maliciousness", degraded, "reputation")
		}
		return decision(verdict.Allow, "reputation.informational", "weak reputation evidence alone does not justify a hold", degraded, "reputation")
	}

	return decision(verdict.Allow, "core.policy-satisfied", "available evidence satisfies the configured policy", degraded)
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
}

func decision(kind verdict.Kind, ruleID, summary string, degraded bool, signals ...string) verdict.Decision {
	return verdict.Decision{
		Verdict:  kind,
		Reasons:  []verdict.Reason{{RuleID: ruleID, Summary: summary, SignalKinds: signals}},
		Degraded: degraded,
	}
}

// Assess converts an immutable evidence snapshot into an Assessment purely and deterministically using the default high threshold.
func Assess(snap evidence.Snapshot) Assessment {
	return AssessWithThreshold(snap, SeverityHigh)
}

// AssessWithThreshold converts an immutable evidence snapshot into an Assessment evaluating vulnerability observations against the specified threshold.
func AssessWithThreshold(snap evidence.Snapshot, threshold Severity) Assessment {
	var a Assessment

	for _, obs := range snap.Observations() {
		switch obs.Kind {
		case evidence.KindIntegrity:
			if obs.Observation == "mismatch" || obs.Observation == "failed" {
				a.IntegrityMismatch = true
			}
		case evidence.KindMalicious:
			if obs.Observation == "true" || obs.Observation == "malicious" {
				a.KnownMalicious = true
			}
		case evidence.KindVulnerability:
			if obs.Observation == "malicious" {
				a.KnownMalicious = true
			} else if isVulnerabilityAboveThreshold(obs.Observation, threshold) {
				a.VulnerabilityAboveThreshold = true
			}
		case evidence.KindNameConfusion:
			if obs.Observation == "confusion_detected" || obs.Observation == "true" || strings.HasPrefix(obs.Observation, "confusion_detected:") {
				a.StrongNameConfusion = true
				if strings.HasPrefix(obs.Observation, "confusion_detected:") {
					a.ConfusedWith = strings.TrimPrefix(obs.Observation, "confusion_detected:")
				}
			}
			if strings.HasPrefix(obs.Observation, "target:") {
				a.ConfusedWith = strings.TrimPrefix(obs.Observation, "target:")
			}
		case evidence.KindPublishHistory:
			if obs.Observation == "not_found" || obs.Observation == "package_not_found" || obs.Observation == "version_not_found" {
				a.PackageNotFound = true
			}
		case evidence.KindPackageAge:
			if obs.Observation == "fresh" || obs.Observation == "newborn" {
				a.NewbornOrFresh = true
			} else if obs.Observation == "not_found" {
				a.PackageNotFound = true
			}
		case evidence.KindProvenance:
			if obs.Observation == "changed" || obs.Observation == "unexpected" {
				a.PublisherOrProvenanceChanged = true
			}
		case evidence.KindInstallScript:
			if obs.Observation == "script_added" {
				a.InstallScriptAdded = true
				a.HasInstallScriptOrNativeBuild = true
			} else if obs.Observation == "present" || obs.Observation == "native_build" {
				a.HasInstallScriptOrNativeBuild = true
			} else if obs.Observation == "inspect_truncated" {
				a.InspectionTruncated = true
			} else if strings.HasPrefix(obs.Observation, "indicator:") {
				a.DangerousInstallScript = true
				a.HasInstallScriptOrNativeBuild = true
				parts := strings.Split(obs.Observation, ":")
				if len(parts) >= 4 && parts[2] == "script" {
					a.DangerousScriptNames = append(a.DangerousScriptNames, parts[3])
					a.DangerousScriptReasons = append(a.DangerousScriptReasons, fmt.Sprintf("%s indicator in %s", parts[1], parts[3]))
				}
			} else if strings.HasPrefix(obs.Observation, "dangerous_script:") {
				a.DangerousInstallScript = true
				a.HasInstallScriptOrNativeBuild = true
				scriptName := strings.TrimPrefix(obs.Observation, "dangerous_script:")
				a.DangerousScriptNames = append(a.DangerousScriptNames, scriptName)
			}
		case evidence.KindReputation:
			if obs.Observation == "low_popularity" {
				a.LowPopularity = true
			} else if obs.Observation == "missing_repository" {
				a.MissingRepository = true
			}
		case evidence.KindCache:
			if obs.Observation == "fresh_allow" {
				a.FreshCachedAllow = true
			}
		case evidence.KindAvailability:
			if obs.Observation == "unavailable" {
				a.EvidenceUnavailable = true
			}
		}

		if obs.Observation == "unavailable" {
			a.EvidenceUnavailable = true
		}
	}

	if snap.HasUnavailableEvidence() {
		a.EvidenceUnavailable = true
	}

	return a
}

func isVulnerabilityAboveThreshold(obs string, threshold Severity) bool {
	if obs == "above_threshold" {
		return true
	}
	if obs == "below_threshold" || obs == "none" || obs == "no_record_found" {
		return false
	}

	obsRank, err := parseSeverityRank(obs)
	if err != nil {
		return false
	}

	targetRank, ok := severityRanks[threshold]
	if !ok {
		targetRank = severityRanks[SeverityHigh]
	}

	return obsRank >= targetRank
}

func parseSeverityRank(s string) (int, error) {
	switch strings.ToLower(s) {
	case "critical":
		return 4, nil
	case "high":
		return 3, nil
	case "medium", "moderate":
		return 2, nil
	case "low":
		return 1, nil
	default:
		return 0, fmt.Errorf("unknown severity: %s", s)
	}
}

// EvaluateSnapshot applies the deterministic foundation policy to an immutable evidence snapshot.
// It touches neither the clock nor the network.
func EvaluateSnapshot(profile Profile, snap evidence.Snapshot) verdict.Decision {
	return Evaluate(profile, Assess(snap))
}
