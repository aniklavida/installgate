package policy

import (
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
}

// Evaluate applies the current deterministic foundation policy.
func Evaluate(profile Profile, a Assessment) verdict.Decision {
	if a.IntegrityMismatch || a.KnownMalicious {
		return decision(verdict.Block, "core.integrity-or-malicious", "integrity mismatch or known malicious evidence", false, "integrity", "malicious")
	}
	if a.VulnerabilityAboveThreshold {
		return decision(verdict.Block, "core.vulnerability-threshold", "vulnerability exceeds the configured threshold", false, "vulnerability")
	}
	if a.EvidenceUnavailable {
		if profile == Balanced && a.FreshCachedAllow {
			return decision(verdict.Allow, "availability.fresh-cache", "live evidence is unavailable; a fresh cached allow remains usable with a stale-evidence warning", true, "availability", "cache")
		}
		if profile == Strict && !a.FreshCachedAllow {
			return decision(verdict.Block, "availability.strict", "required evidence is unavailable under the strict profile", true, "availability")
		}
		return decision(verdict.ApprovalRequired, "availability.no-cache", "required evidence is unavailable and no usable cached allow exists", true, "availability")
	}
	if a.StrongNameConfusion && a.NewbornOrFresh {
		if profile == Strict {
			return decision(verdict.Block, "identity.confusable-new", "a strongly confusing package name is corroborated by package freshness", false, "name_confusion", "package_age")
		}
		return decision(verdict.ApprovalRequired, "identity.confusable-new", "a strongly confusing package name is corroborated by package freshness", false, "name_confusion", "package_age")
	}
	if a.PublisherOrProvenanceChanged && a.InstallScriptAdded {
		if profile == Strict {
			return decision(verdict.Block, "release.provenance-script-change", "publisher or provenance changed when an install script was added", false, "provenance", "install_script")
		}
		return decision(verdict.ApprovalRequired, "release.provenance-script-change", "publisher or provenance changed when an install script was added", false, "provenance", "install_script")
	}
	if a.HasInstallScriptOrNativeBuild {
		if profile == Strict {
			return decision(verdict.ApprovalRequired, "execution.install-time", "the package can execute install-time code", false, "install_script")
		}
		return decision(verdict.Warn, "execution.install-time", "the package can execute install-time code", false, "install_script")
	}
	if a.LowPopularity || a.MissingRepository {
		if profile == Strict {
			return decision(verdict.Warn, "reputation.weak-signal", "weak reputation evidence is informational and not proof of maliciousness", false, "reputation")
		}
		return decision(verdict.Allow, "reputation.informational", "weak reputation evidence alone does not justify a hold", false, "reputation")
	}
	return decision(verdict.Allow, "core.policy-satisfied", "available evidence satisfies the configured policy", false)
}

func decision(kind verdict.Kind, ruleID, summary string, degraded bool, signals ...string) verdict.Decision {
	return verdict.Decision{
		Verdict:  kind,
		Reasons:  []verdict.Reason{{RuleID: ruleID, Summary: summary, SignalKinds: signals}},
		Degraded: degraded,
	}
}

// Assess converts an immutable evidence snapshot into an Assessment purely and deterministically.
func Assess(snap evidence.Snapshot) Assessment {
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
			if obs.Observation == "above_threshold" || obs.Observation == "critical" || obs.Observation == "high" {
				a.VulnerabilityAboveThreshold = true
			} else if obs.Observation == "malicious" {
				a.KnownMalicious = true
			}
		case evidence.KindNameConfusion:
			if obs.Observation == "confusion_detected" || obs.Observation == "true" {
				a.StrongNameConfusion = true
			}
		case evidence.KindPackageAge:
			if obs.Observation == "fresh" || obs.Observation == "newborn" {
				a.NewbornOrFresh = true
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

// EvaluateSnapshot applies the deterministic foundation policy to an immutable evidence snapshot.
// It touches neither the clock nor the network.
func EvaluateSnapshot(profile Profile, snap evidence.Snapshot) verdict.Decision {
	return Evaluate(profile, Assess(snap))
}
