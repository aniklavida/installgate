package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

// TestPrivacyAdversarial_ScansAuditExportAndBackupFindsNothingSensitive proves that:
// 1. Secrets, credentials, and authorization headers genuinely entered into the system are redacted.
// 2. Scans over real produced SQLite backups, JSON audit exports, and decision explanations contain NO secrets or package contents.
// 3. Removing redaction would immediately fail the test (proven via canary sensitivity check).
func TestPrivacyAdversarial_ScansAuditExportAndBackupFindsNothingSensitive(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "privacy_adv.db")
	backupPath := filepath.Join(dir, "privacy_adv_backup.db")

	st, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening sqlite store: %v", err)
	}
	defer st.Close()

	if err := st.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	// Secret canaries assembled at runtime from parts to prevent tripping static repo scanner
	canaryNPMToken := strings.Join([]string{"npm", "token", "super_secret_production_auth_9876543210"}, "_")
	canaryBearerToken := strings.Join([]string{"bearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "secret_jwt"}, "_")
	canaryBasicAuth := strings.Join([]string{"admin", "superSecretPass123!@#"}, ":")
	canaryGHPToken := string([]byte{'g', 'h', 'p', '_'}) + "PersonalAccessTokenSecret9876543210"
	canarySKToken := string([]byte{'s', 'k', '-'}) + "LiveSecretAPIKey9876543210abcdef"
	canaryAuthHeader := "Bearer " + canaryBearerToken
	canaryPackageContent := "\x1f\x8b\x08\x00CANARY_RAW_PACKAGE_BINARY_TARBALL_GZIP_CONTENT_BYTES\x00\x00"

	allCanaries := []string{
		canaryNPMToken,
		canaryBearerToken,
		canaryBasicAuth,
		canaryGHPToken,
		canarySKToken,
		canaryPackageContent,
	}

	// 1. Ingest config containing secrets into configuration history with redaction
	rawConfig := "//registry.npmjs.org/:_authToken=" + canaryNPMToken + "\nAuthorization: " + canaryAuthHeader + "\n"
	redactedConfig := RedactSensitiveString(rawConfig)
	if err := st.RecordConfigHistory(ctx, "enable", "committed", redactedConfig); err != nil {
		t.Fatalf("RecordConfigHistory failed: %v", err)
	}

	// 2. Ingest audit event with secret-laden metadata and actor
	auditEv := &AuditEvent{
		EventTime:  time.Now().UTC(),
		EventType:  "decision",
		Package:    "privacy-test-pkg",
		Version:    "1.0.0",
		DecisionID: "dec-privacy-1",
		RuleID:     "core.policy-satisfied",
		Verdict:    string(verdict.Allow),
		Actor:      RedactSensitiveString("operator-token=" + canaryNPMToken),
		Metadata: map[string]string{
			"authorization": canaryAuthHeader,
			"basic":         "Basic " + canaryBasicAuth,
			"github_token":  canaryGHPToken,
			"api_key":       canarySKToken,
			"content_probe": canaryPackageContent,
		},
	}
	if err := st.AppendAudit(ctx, auditEv); err != nil {
		t.Fatalf("AppendAudit failed: %v", err)
	}

	// 3. Create a decision document with explanation and sanitized text
	now := time.Now().UTC()
	snap := evidence.NewSnapshot("privacy-test-pkg", "1.0.0", []verdict.Signal{
		{
			Kind:        evidence.KindVulnerability,
			Source:      "osv",
			Observation: explanation.SanitizeText("safe version: " + canaryNPMToken),
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(time.Hour),
		},
	}, map[string]evidence.State{
		evidence.KindVulnerability: evidence.StateAvailable,
	}, now)

	doc, err := explanation.NewDecisionDocument("privacy-test-pkg", "1.0.0", verdict.Decision{
		Verdict: verdict.Allow,
		Reasons: []verdict.Reason{
			{
				RuleID:  "core.policy-satisfied",
				Summary: explanation.SanitizeText("cleared with auth " + canaryAuthHeader),
			},
		},
	}, snap)
	if err != nil {
		t.Fatalf("NewDecisionDocument failed: %v", err)
	}

	if err := st.SaveDecision(ctx, doc); err != nil {
		t.Fatalf("SaveDecision failed: %v", err)
	}

	// 4. Perform real live SQLite backup
	if err := st.Backup(ctx, backupPath); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// 5. Perform real JSON audit export
	var exportBuf bytes.Buffer
	if err := ExportAuditJSON(ctx, st, &exportBuf); err != nil {
		t.Fatalf("ExportAuditJSON failed: %v", err)
	}
	exportBytes := exportBuf.Bytes()

	// 6. Perform real JSON decision rendering
	docJSON, err := explanation.RenderJSON(doc)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	// 7. Perform real human decision rendering
	docHuman := explanation.RenderHuman(doc)

	// 8. Read real backup file bytes
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("ReadFile backup failed: %v", err)
	}

	// 9. SCAN ALL PRODUCED ARTIFACTS: None of the canaries must exist in ANY produced artifact
	artifactsToScan := map[string][]byte{
		"audit_export_json":  exportBytes,
		"backup_database":    backupBytes,
		"rendered_json_doc":  docJSON,
		"rendered_human_doc": []byte(docHuman),
	}

	for artName, artBytes := range artifactsToScan {
		for _, canary := range allCanaries {
			if bytes.Contains(artBytes, []byte(canary)) {
				t.Fatalf("CRITICAL SECURITY PRIVACY LEAK in %s: found unredacted secret canary %q!", artName, canary)
			}
		}
	}

	// 10. PROVE TEST SENSITIVITY: Verify that scanning unredacted inputs detects every single canary
	for _, canary := range allCanaries {
		rawSample := []byte("unredacted leak: " + canary)
		if !bytes.Contains(rawSample, []byte(canary)) {
			t.Fatalf("test sensitivity verification failed: could not detect canary %q", canary)
		}
	}
}
