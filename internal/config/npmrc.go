package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// ErrUnsupportedAuth is returned when an npmrc contains authentication tokens or credentials.
	ErrUnsupportedAuth = errors.New("unsupported configuration: authenticated npm configuration detected in .npmrc; InstallGate only supports unauthenticated registry access")

	// ErrUnsupportedScopedRegistry is returned when an npmrc contains scoped registry routing.
	ErrUnsupportedScopedRegistry = errors.New("unsupported configuration: scoped registry configuration detected; InstallGate only supports the public npm registry")
)

var (
	registryKeyRegex = regexp.MustCompile(`^(?i)\s*registry\s*=\s*(.*?)\s*$`)
	scopedKeyRegex   = regexp.MustCompile(`^(?i)\s*@.*?:\s*registry\s*=`)
	authPatternRegex = regexp.MustCompile(`(?i)(_authToken|_auth|_password|always-auth\s*=\s*true)`)
)

// NpmrcInfo holds inspection data for a target .npmrc file.
type NpmrcInfo struct {
	Path            string
	Exists          bool
	RawContent      []byte
	Lines           []string
	HasRegistry     bool
	RegistryValue   string
	RegistryLineIdx int
	LineEnding      string
}

// DefaultNpmrcPath returns the resolved path to the user's .npmrc file.
// Honors NPM_CONFIG_USERCONFIG when set; otherwise falls back to ~/.npmrc.
func DefaultNpmrcPath() string {
	if p := os.Getenv("NPM_CONFIG_USERCONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".npmrc")
	}
	return ".npmrc"
}

// InspectNpmrc inspects an npm configuration file and validates compatibility.
// If unsupported authentication credentials or private registries are detected,
// it refuses with an explanatory error. Authentication tokens are NEVER logged or stored.
func InspectNpmrc(path string) (*NpmrcInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &NpmrcInfo{
				Path:            path,
				Exists:          false,
				RegistryLineIdx: -1,
				LineEnding:      "\n",
			}, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	info := &NpmrcInfo{
		Path:            path,
		Exists:          true,
		RawContent:      data,
		RegistryLineIdx: -1,
		LineEnding:      detectLineEnding(data),
	}

	// Split content into lines preserving line structure
	rawLines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	// If file ended with trailing newline, Split produces an empty trailing element
	info.Lines = rawLines

	for idx, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		// 1. Check for authentication tokens / credentials
		if authPatternRegex.MatchString(trimmed) {
			return nil, ErrUnsupportedAuth
		}

		// 2. Check for scoped registry
		if scopedKeyRegex.MatchString(trimmed) {
			return nil, ErrUnsupportedScopedRegistry
		}

		// 3. Check for primary registry setting
		if m := registryKeyRegex.FindStringSubmatch(line); m != nil {
			info.HasRegistry = true
			info.RegistryValue = m[1]
			info.RegistryLineIdx = idx
		}
	}

	// Validate existing registry value if present
	if info.HasRegistry {
		if err := validateRegistryURL(info.RegistryValue, path); err != nil {
			return nil, err
		}
	}

	return info, nil
}

func validateRegistryURL(rawURL, path string) error {
	trimmed := strings.Trim(strings.TrimSpace(rawURL), `"'`)
	if trimmed == "" {
		return nil
	}

	norm := strings.TrimSuffix(trimmed, "/")
	// Public npm URLs
	if norm == "https://registry.npmjs.org" || norm == "http://registry.npmjs.org" {
		return nil
	}

	// Allow existing loopback gateway URLs (e.g. if already pointed at InstallGate)
	if u, err := url.Parse(trimmed); err == nil {
		host := u.Hostname()
		if host == "127.0.0.1" || host == "localhost" {
			return nil
		}
	}

	return fmt.Errorf("unsupported configuration: private registry %q detected in %s; InstallGate only supports the public npm registry (https://registry.npmjs.org)", trimmed, path)
}

func detectLineEnding(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// GenerateEnabledContent generates the updated .npmrc bytes pointing to gatewayURL.
func GenerateEnabledContent(info *NpmrcInfo, gatewayURL string) []byte {
	targetLine := "registry=" + ensureTrailingSlash(gatewayURL)

	if !info.Exists {
		return []byte(targetLine + "\n")
	}

	le := info.LineEnding
	if info.HasRegistry && info.RegistryLineIdx >= 0 && info.RegistryLineIdx < len(info.Lines) {
		lines := make([]string, len(info.Lines))
		copy(lines, info.Lines)
		lines[info.RegistryLineIdx] = targetLine
		return []byte(strings.Join(lines, le))
	}

	// No registry key in existing file: append
	raw := string(info.RawContent)
	if len(raw) == 0 {
		return []byte(targetLine + le)
	}

	if strings.HasSuffix(raw, "\n") || strings.HasSuffix(raw, "\r\n") {
		return []byte(raw + targetLine + le)
	}
	return []byte(raw + le + targetLine + le)
}

// GenerateRestoredContent produces the exact prior bytes for restoring .npmrc.
// If the file did not exist prior to enable, shouldDelete is true.
func GenerateRestoredContent(currentContent []byte, prior PriorConfig) (restored []byte, shouldDelete bool) {
	if !prior.FileExisted {
		return nil, true
	}

	// Byte-for-byte restore of original raw content
	return prior.RawContent, false
}

func ensureTrailingSlash(u string) string {
	if !strings.HasSuffix(u, "/") {
		return u + "/"
	}
	return u
}
