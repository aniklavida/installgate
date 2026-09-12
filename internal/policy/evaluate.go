package policy

import "github.com/aniklavida/installgate/internal/verdict"

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
