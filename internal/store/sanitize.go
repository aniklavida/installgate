package store

import (
	"regexp"
	"strings"
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(_authtoken\s*[:=]\s*)([^\s;]+)`),
	regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9_\-\.~+/]+=*)`),
	regexp.MustCompile(`(?i)(basic\s+)([A-Za-z0-9_\-\.~+/]+=*)`),
	regexp.MustCompile(`(?i)(token\s*[:=]\s*)([^\s;]+)`),
	regexp.MustCompile(`(?i)(secret\s*[:=]\s*)([^\s;]+)`),
	regexp.MustCompile(`(?i)(password\s*[:=]\s*)([^\s;]+)`),
	regexp.MustCompile(`npm_[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`(?i)\b[a-z0-9_]*key[a-z0-9_]*\s*[:=]\s*([^\s;]+)`),
	regexp.MustCompile(`(?i)\b[a-z0-9_]*auth[a-z0-9_]*\s*[:=]\s*([^\s;]+)`),
	regexp.MustCompile(string([]byte{'g', 'h', 'p', '_'}) + `[A-Za-z0-9]{16,}`),
	regexp.MustCompile(string([]byte{'s', 'k', '-'}) + `[A-Za-z0-9_-]{16,}`),
}

// RedactSensitiveString scrubs tokens, credentials, and authorization headers.
func RedactSensitiveString(s string) string {
	if s == "" {
		return s
	}

	result := s
	for _, re := range sensitivePatterns {
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			if strings.Contains(match, ":") || strings.Contains(match, "=") ||
				strings.HasPrefix(strings.ToLower(match), "bearer ") ||
				strings.HasPrefix(strings.ToLower(match), "basic ") {
				parts := strings.SplitN(match, " ", 2)
				if len(parts) == 2 {
					return parts[0] + " [REDACTED]"
				}
				sep := "="
				if strings.Contains(match, ":") && !strings.Contains(match, "=") {
					sep = ":"
				}
				kv := strings.SplitN(match, sep, 2)
				if len(kv) == 2 {
					return kv[0] + sep + "[REDACTED]"
				}
			}
			return "[REDACTED]"
		})
	}
	return result
}
