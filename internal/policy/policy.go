package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
	"gopkg.in/yaml.v3"
)

// CurrentPolicyVersion is the supported schema version for repository-local policy.
const CurrentPolicyVersion = "1"

// DefaultPolicyFileName is the conventional repository-local policy filename.
const DefaultPolicyFileName = "installgate.yaml"

// BoundsStatement declares the explicit bounds of repository-local policy customization:
// what may be tightened and what may not be loosened.
const BoundsStatement = `InstallGate repository policy bounds:
What repository policy may tighten:
- profile: configure "balanced" (default) or "strict"
- vulnerability_threshold: configure "critical", "high" (default), "medium", or "low"

What repository policy may NOT loosen:
- Core invariants: integrity mismatches and known malicious packages always block
- Evidence availability: provider outages always degrade decisions and cannot be ignored
- Reputation limits: low popularity or missing repository alone can never produce approval_required or block
- Determinism: decisions must remain deterministic functions of policy, input, and evidence`

// PolicyBoundsStatement returns the explicit bounds statement for repository-local policy.
func PolicyBoundsStatement() string {
	return BoundsStatement
}

// Severity represents a vulnerability severity threshold.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRanks = map[Severity]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Valid reports whether the severity threshold is recognized.
func (s Severity) Valid() bool {
	_, ok := severityRanks[s]
	return ok
}

// Rank returns the numeric ordering of the severity threshold.
func (s Severity) Rank() int {
	return severityRanks[s]
}

// Policy holds validated repository-local configuration governing policy evaluation.
type Policy struct {
	Version                string   `json:"version" yaml:"version"`
	Profile                Profile  `json:"profile" yaml:"profile"`
	VulnerabilityThreshold Severity `json:"vulnerability_threshold" yaml:"vulnerability_threshold"`
}

// BoundsStatement returns the explicit bounds statement for repository-local policy.
func (p *Policy) BoundsStatement() string {
	return BoundsStatement
}

// NewDefaultPolicy constructs a policy using balanced profile and high vulnerability threshold.
func NewDefaultPolicy() *Policy {
	return &Policy{
		Version:                CurrentPolicyVersion,
		Profile:                Balanced,
		VulnerabilityThreshold: SeverityHigh,
	}
}

// ValidatePolicy checks that the policy conforms to schema version and tightening boundaries.
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return errors.New("policy is nil")
	}

	if p.Version == "" {
		return fmt.Errorf("field \"version\": version is required")
	}
	if p.Version != CurrentPolicyVersion {
		return fmt.Errorf("field \"version\": unsupported policy version %q, supported version is %q", p.Version, CurrentPolicyVersion)
	}

	switch p.Profile {
	case Balanced, Strict:
	case "":
		return fmt.Errorf("field \"profile\": profile is required, must be \"balanced\" or \"strict\"")
	default:
		return fmt.Errorf("field \"profile\": invalid profile %q, must be \"balanced\" or \"strict\"", p.Profile)
	}

	switch p.VulnerabilityThreshold {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	case "":
		return fmt.Errorf("field \"vulnerability_threshold\": vulnerability_threshold is required, must be one of \"critical\", \"high\", \"medium\", \"low\"")
	default:
		return fmt.Errorf("field \"vulnerability_threshold\": invalid threshold %q, must be one of \"critical\", \"high\", \"medium\", \"low\"", p.VulnerabilityThreshold)
	}

	return nil
}

// ParsePolicy decodes and validates policy YAML from raw bytes.
// Unknown fields and forbidden loosening directives are rejected with actionable messages.
func ParsePolicy(data []byte) (*Policy, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("field \"version\": empty policy content, version is required")
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("malformed policy YAML: %w", err)
	}

	// Reject explicit attempts to loosen non-loosening core invariants
	if _, ok := raw["allow_malicious"]; ok {
		return nil, fmt.Errorf("field \"allow_malicious\": known malicious packages cannot be allowed or loosened")
	}
	if _, ok := raw["ignore_integrity"]; ok {
		return nil, fmt.Errorf("field \"ignore_integrity\": integrity verification cannot be disabled or loosened")
	}
	if _, ok := raw["ignore_outages"]; ok {
		return nil, fmt.Errorf("field \"ignore_outages\": evidence provider outages cannot be ignored or treated as clean")
	}
	if val, ok := raw["reputation"]; ok {
		s := fmt.Sprintf("%v", val)
		if strings.Contains(s, "block") || strings.Contains(s, "approval") {
			return nil, fmt.Errorf("field \"reputation\": low popularity or missing repository cannot independently produce approval_required or block")
		}
	}
	if val, ok := raw["low_popularity"]; ok {
		s := fmt.Sprintf("%v", val)
		if strings.Contains(s, "block") || strings.Contains(s, "approval") {
			return nil, fmt.Errorf("field \"low_popularity\": low popularity cannot independently produce approval_required or block")
		}
	}

	p := &Policy{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(p); err != nil {
		msg := err.Error()
		if idx := strings.Index(msg, "field "); idx != -1 {
			rem := msg[idx+len("field "):]
			if end := strings.Index(rem, " "); end != -1 {
				fieldName := rem[:end]
				return nil, fmt.Errorf("field %q: unknown field not permitted in policy", fieldName)
			}
		}
		return nil, fmt.Errorf("malformed policy YAML: %w", err)
	}

	// Normalize casing for profile and severity
	p.Profile = Profile(strings.ToLower(string(p.Profile)))
	p.VulnerabilityThreshold = Severity(strings.ToLower(string(p.VulnerabilityThreshold)))

	if err := ValidatePolicy(p); err != nil {
		return nil, err
	}

	return p, nil
}

// LoadPolicyFile reads and validates a repository-local policy file from disk.
func LoadPolicyFile(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %q: %w", filePath, err)
	}
	return ParsePolicy(data)
}

// LoadDefaultPolicy searches for installgate.yaml or .installgate.yaml in the specified directory.
// If neither exists, it returns a default policy.
func LoadDefaultPolicy(dir string) (*Policy, error) {
	candidates := []string{
		filepath.Join(dir, DefaultPolicyFileName),
		filepath.Join(dir, ".installgate.yaml"),
		filepath.Join(dir, ".installgate.yml"),
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return LoadPolicyFile(path)
		}
	}

	return NewDefaultPolicy(), nil
}

// Evaluate applies the configured policy profile to an assessment.
func (p *Policy) Evaluate(a Assessment) verdict.Decision {
	return Evaluate(p.Profile, a)
}

// Assess converts an immutable snapshot into an Assessment according to the configured threshold.
func (p *Policy) Assess(snap evidence.Snapshot) Assessment {
	return AssessWithThreshold(snap, p.VulnerabilityThreshold)
}

// EvaluateSnapshot applies the policy directly to an immutable evidence snapshot.
func (p *Policy) EvaluateSnapshot(snap evidence.Snapshot) verdict.Decision {
	return p.Evaluate(p.Assess(snap))
}
