package explanation

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	bearerRegex     = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9_\-\.~+/]+=*`)
	basicRegex      = regexp.MustCompile(`(?i)(basic\s+)[A-Za-z0-9_\-\.~+/]+=*`)
	authHeaderRegex = regexp.MustCompile(`(?i)(authorization:\s*)([^\r\n]+)`)
	proxyAuthRegex  = regexp.MustCompile(`(?i)(proxy-authorization:\s*)([^\r\n]+)`)
	urlCredsRegex   = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^:@\s]+):([^@\s]+)@`)
	npmTokenRegex   = regexp.MustCompile(`\b(npm_[A-Za-z0-9]{20,})\b`)
	ghTokenRegex    = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,})\b`)
	skTokenRegex    = regexp.MustCompile(`\b(s[k]-[A-Za-z0-9]{16,})\b`)
	ntnTokenRegex   = regexp.MustCompile(`\b(n[t]n_[A-Za-z0-9]{16,})\b`)
	authTokenRegex  = regexp.MustCompile(`(?i)(_authtoken\s*=\s*)([^\s\r\n]+)`)
)

// SanitizeText removes credentials, authorization headers, and secret tokens from text.
func SanitizeText(s string) string {
	if s == "" {
		return ""
	}

	res := s
	res = authHeaderRegex.ReplaceAllString(res, "${1}[REDACTED]")
	res = proxyAuthRegex.ReplaceAllString(res, "${1}[REDACTED]")
	res = bearerRegex.ReplaceAllString(res, "${1}[REDACTED]")
	res = basicRegex.ReplaceAllString(res, "${1}[REDACTED]")
	res = urlCredsRegex.ReplaceAllString(res, "${1}[REDACTED]:[REDACTED]@")
	res = npmTokenRegex.ReplaceAllString(res, "[REDACTED_NPM_TOKEN]")
	res = ghTokenRegex.ReplaceAllString(res, "[REDACTED_TOKEN]")
	res = skTokenRegex.ReplaceAllString(res, "[REDACTED_KEY]")
	res = ntnTokenRegex.ReplaceAllString(res, "[REDACTED_KEY]")
	res = authTokenRegex.ReplaceAllString(res, "${1}[REDACTED_TOKEN]")

	// Strip non-printable / binary characters that indicate package tarball contents
	if containsBinaryContent(res) {
		return "[PACKAGE_CONTENT_REDACTED]"
	}

	return res
}

func containsBinaryContent(s string) bool {
	if len(s) > 4096 {
		return true
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == 0 {
			return true
		}
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return true
		}
	}
	return false
}

// ValidateCoordinates ensures package name and version are safe coordinates
// free of injection attempts or control characters.
func ValidateCoordinates(pkg, version string) error {
	if strings.TrimSpace(pkg) == "" {
		return fmt.Errorf("package coordinate is required")
	}
	if strings.TrimSpace(version) == "" {
		return fmt.Errorf("package version coordinate is required")
	}
	if strings.ContainsAny(pkg, "\r\n\x00") || strings.ContainsAny(version, "\r\n\x00") {
		return fmt.Errorf("coordinates contain invalid control characters")
	}
	if strings.Contains(pkg, "://") || strings.Contains(version, "://") {
		return fmt.Errorf("coordinates cannot contain URLs or scheme prefixes")
	}
	return nil
}
