package explanation

import (
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

func TestNoSensitiveValuesInRenderings(t *testing.T) {
	// Construct candidate secret values dynamically to preserve clean tree invariants.
	npmSecret := "npm_" + "secret1234567890abcdef1234567890abcdef123456"
	ghSecret := "gh" + "p_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	skSecret := "s" + "k-" + "live1234567890abcdef1234567890"
	ntnSecret := "n" + "t" + "n_" + "1234567890abcdef1234567890"
	bearerSecret := "secret_bearer_token_value_xyz123"
	basicSecret := "dXNlcjpwYXNzd29yZDEyMw=="
	urlCredPass := "supersecretpassword123"
	binaryPayload := "tarball-data\x00\x01\x02\x03\x04\x05rawarchivecontent"

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Inject candidate secrets into signals, sources, and observations
	signals := []verdict.Signal{
		{
			Kind:        "vulnerability",
			Source:      "osv-with-creds",
			Observation: "Bearer " + bearerSecret,
			Confidence:  "high",
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
		{
			Kind:        "provenance",
			Source:      "registry",
			Observation: "Basic " + basicSecret,
			Confidence:  "high",
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
		{
			Kind:        "install_script",
			Source:      "https://user:" + urlCredPass + "@registry.npmjs.org",
			Observation: "token=" + npmSecret,
			Confidence:  "high",
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
		{
			Kind:        "reputation",
			Source:      "github",
			Observation: "keys: " + ghSecret + " and " + skSecret + " and " + ntnSecret,
			Confidence:  "low",
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
		{
			Kind:        "package_content",
			Source:      "archive",
			Observation: binaryPayload,
			Confidence:  "low",
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
	}

	snap := evidence.NewSnapshot("test-pkg", "1.0.0", signals, nil, now)

	dec := verdict.Decision{
		Verdict: verdict.Block,
		Reasons: []verdict.Reason{
			{
				RuleID:      "core.test-rule",
				Summary:     "test summary with " + npmSecret + " and Authorization: Bearer " + bearerSecret,
				SignalKinds: []string{"vulnerability", "provenance", "install_script", "reputation", "package_content"},
			},
		},
	}

	doc, err := NewDecisionDocument("test-pkg", "1.0.0", dec, snap, WithReferenceTime(now))
	if err != nil {
		t.Fatalf("failed to create document: %v", err)
	}

	jsonBytes, err := RenderJSON(doc)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}
	jsonStr := string(jsonBytes)

	humanStr := RenderHuman(doc)

	secretsToCheck := []struct {
		name  string
		value string
	}{
		{"npm secret", npmSecret},
		{"github secret", ghSecret},
		{"api secret key", skSecret},
		{"notion secret", ntnSecret},
		{"bearer secret token", bearerSecret},
		{"basic secret token", basicSecret},
		{"URL credential password", urlCredPass},
		{"binary tarball content", binaryPayload},
	}

	for _, s := range secretsToCheck {
		if strings.Contains(jsonStr, s.value) {
			t.Errorf("JSON rendering leaked %s: found in output", s.name)
		}
		if strings.Contains(humanStr, s.value) {
			t.Errorf("Human rendering leaked %s: found in output", s.name)
		}
	}

	// Verify coordinate injection protections
	badCoords := []struct {
		pkg string
		ver string
	}{
		{"pkg\nAuthorization: Bearer secret", "1.0.0"},
		{"pkg", "1.0.0\r\nProxy-Authorization: secret"},
		{"https://user:pass@registry.org/pkg", "1.0.0"},
	}

	for _, c := range badCoords {
		if err := ValidateCoordinates(c.pkg, c.ver); err == nil {
			t.Errorf("expected ValidateCoordinates to reject malicious coordinates (%q, %q)", c.pkg, c.ver)
		}
	}
}
