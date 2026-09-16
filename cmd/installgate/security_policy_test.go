package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityPolicy_DocumentationAndPrivateChannelConfigured asserts that SECURITY.md exists
// and defines a working private vulnerability reporting channel.
func TestSecurityPolicy_DocumentationAndPrivateChannelConfigured(t *testing.T) {
	// Root SECURITY.md
	secPath := filepath.Join("..", "..", "SECURITY.md")
	content, err := os.ReadFile(secPath)
	if err != nil {
		t.Fatalf("SECURITY.md must exist at repository root: %v", err)
	}

	secText := string(content)

	// Assert required sections and channel declarations
	if !strings.Contains(secText, "Reporting a vulnerability") {
		t.Error("SECURITY.md missing 'Reporting a vulnerability' section")
	}

	if !strings.Contains(secText, "GitHub private vulnerability reporting") {
		t.Error("SECURITY.md must explicitly direct reporters to GitHub private vulnerability reporting")
	}

	if !strings.Contains(secText, "Do not open a public issue") {
		t.Error("SECURITY.md must explicitly forbid public issues for vulnerabilities")
	}
}

// TestSecurityPolicy_LiveReportingFlow_RequiresHuman skips with an explicit explanation
// because an unattended automated session must never submit live vulnerability reports to GitHub.
func TestSecurityPolicy_LiveReportingFlow_RequiresHuman(t *testing.T) {
	t.Skip("manual pre-release step: unattended test session cannot dispatch real report through GitHub private vulnerability advisory channel; requires human security officer to verify private reporting flow end-to-end")
}
