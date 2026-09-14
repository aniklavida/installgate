package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectNpmrc_NoFile(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, ".npmrc")

	info, err := InspectNpmrc(path)
	if err != nil {
		t.Fatalf("InspectNpmrc failed: %v", err)
	}
	if info.Exists {
		t.Errorf("expected Exists=false, got true")
	}
	if info.HasRegistry {
		t.Errorf("expected HasRegistry=false, got true")
	}
}

func TestInspectNpmrc_PublicRegistry(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, ".npmrc")
	content := []byte("# comment\nregistry=https://registry.npmjs.org/\nsave-exact=true\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := InspectNpmrc(path)
	if err != nil {
		t.Fatalf("InspectNpmrc failed: %v", err)
	}
	if !info.Exists {
		t.Errorf("expected Exists=true")
	}
	if !info.HasRegistry {
		t.Errorf("expected HasRegistry=true")
	}
	if info.RegistryValue != "https://registry.npmjs.org/" {
		t.Errorf("got %q, want https://registry.npmjs.org/", info.RegistryValue)
	}
	if info.RegistryLineIdx != 1 {
		t.Errorf("got line idx %d, want 1", info.RegistryLineIdx)
	}
}

func TestInspectNpmrc_RefuseAuthTokens(t *testing.T) {
	secretToken := "npm_super_secret_token_12345678"
	cases := []struct {
		name    string
		content string
	}{
		{"direct auth token", "_authToken=" + secretToken + "\n"},
		{"scoped registry token", "//registry.npmjs.org/:_authToken=" + secretToken + "\n"},
		{"legacy auth", "_auth=" + secretToken + "\n"},
		{"password setting", "_password=" + secretToken + "\n"},
		{"always-auth", "always-auth=true\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, ".npmrc")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := InspectNpmrc(path)
			if err == nil {
				t.Fatalf("expected error refusing authenticated config, got nil")
			}

			// Invariant: NPM AUTH TOKENS ARE NEVER LOGGED OR LEAKED IN ERRORS
			errStr := err.Error()
			if strings.Contains(errStr, secretToken) {
				t.Fatalf("SECURITY VIOLATION: auth token leaked in error message: %s", errStr)
			}
			if !strings.Contains(errStr, "authenticated npm configuration detected") {
				t.Errorf("unexpected error message: %s", errStr)
			}

			// Verify file was not touched
			current, _ := os.ReadFile(path)
			if !bytes.Equal(current, []byte(tc.content)) {
				t.Errorf("file was modified despite refusal")
			}
		})
	}
}

func TestInspectNpmrc_RefusePrivateRegistry(t *testing.T) {
	cases := []struct {
		name     string
		registry string
	}{
		{"github packages", "https://npm.pkg.github.com/myorg"},
		{"custom artifactory", "https://artifactory.mycorp.internal/npm"},
		{"private domain", "https://registry.corp.io/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, ".npmrc")
			content := "registry=" + tc.registry + "\n"
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := InspectNpmrc(path)
			if err == nil {
				t.Fatalf("expected error refusing private registry, got nil")
			}
			if !strings.Contains(err.Error(), "private registry") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInspectNpmrc_RefuseScopedRegistry(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, ".npmrc")
	content := "@internal:registry=https://internal.registry.local/\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := InspectNpmrc(path)
	if err == nil {
		t.Fatalf("expected error refusing scoped registry, got nil")
	}
	if !strings.Contains(err.Error(), "scoped registry configuration detected") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEnableAndDisable_ExactRestoration_NoPriorFile(t *testing.T) {
	tempDir := t.TempDir()
	npmrcPath := filepath.Join(tempDir, ".npmrc")
	gatewayURL := "http://127.0.0.1:8765"

	info, err := InspectNpmrc(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	prior := PriorConfig{
		FileExisted: info.Exists,
	}

	// 1. Enable
	enabledContent := GenerateEnabledContent(info, gatewayURL)
	if err := os.WriteFile(npmrcPath, enabledContent, 0o644); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "registry=http://127.0.0.1:8765/") {
		t.Fatalf("enabled content missing registry: %s", string(content))
	}

	// 2. Disable
	_, shouldDelete := GenerateRestoredContent(content, prior)
	if !shouldDelete {
		t.Fatalf("expected shouldDelete=true for previously nonexistent file")
	}
	_ = os.Remove(npmrcPath)

	if _, err := os.Stat(npmrcPath); !os.IsNotExist(err) {
		t.Fatalf("expected file to be completely gone, stat err=%v", err)
	}
}

func TestEnableAndDisable_ExactRestoration_ExistingWithoutRegistry(t *testing.T) {
	tempDir := t.TempDir()
	npmrcPath := filepath.Join(tempDir, ".npmrc")
	originalContent := []byte("# Custom developer settings\nsave-exact=true\npackage-lock=true\n")
	if err := os.WriteFile(npmrcPath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	gatewayURL := "http://127.0.0.1:8765"

	info, err := InspectNpmrc(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	prior := PriorConfig{
		FileExisted: info.Exists,
		HasRegistry: info.HasRegistry,
		RawContent:  info.RawContent,
	}

	// 1. Enable
	enabledContent := GenerateEnabledContent(info, gatewayURL)
	if err := os.WriteFile(npmrcPath, enabledContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Disable
	currentContent, _ := os.ReadFile(npmrcPath)
	restored, shouldDelete := GenerateRestoredContent(currentContent, prior)
	if shouldDelete {
		t.Fatalf("shouldDelete must be false when file previously existed")
	}
	if err := os.WriteFile(npmrcPath, restored, 0o644); err != nil {
		t.Fatal(err)
	}

	finalContent, _ := os.ReadFile(npmrcPath)
	if !bytes.Equal(finalContent, originalContent) {
		t.Fatalf("restoration not byte-for-byte identical:\ngot:\n%s\nwant:\n%s", string(finalContent), string(originalContent))
	}
}

func TestEnableAndDisable_ExactRestoration_ExistingWithPublicRegistry(t *testing.T) {
	tempDir := t.TempDir()
	npmrcPath := filepath.Join(tempDir, ".npmrc")
	originalContent := []byte("; Developer custom config\nregistry = https://registry.npmjs.org/\naudit = false\n")
	if err := os.WriteFile(npmrcPath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	gatewayURL := "http://127.0.0.1:8765"

	info, err := InspectNpmrc(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	prior := PriorConfig{
		FileExisted:   info.Exists,
		HasRegistry:   info.HasRegistry,
		RegistryValue: info.RegistryValue,
		RawContent:    info.RawContent,
	}

	// 1. Enable
	enabledContent := GenerateEnabledContent(info, gatewayURL)
	if err := os.WriteFile(npmrcPath, enabledContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Disable
	currentContent, _ := os.ReadFile(npmrcPath)
	restored, shouldDelete := GenerateRestoredContent(currentContent, prior)
	if shouldDelete {
		t.Fatalf("shouldDelete must be false")
	}
	if err := os.WriteFile(npmrcPath, restored, 0o644); err != nil {
		t.Fatal(err)
	}

	finalContent, _ := os.ReadFile(npmrcPath)
	if !bytes.Equal(finalContent, originalContent) {
		t.Fatalf("restoration not byte-for-byte identical:\ngot:\n%s\nwant:\n%s", string(finalContent), string(originalContent))
	}
}
