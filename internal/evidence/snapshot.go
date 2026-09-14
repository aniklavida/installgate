package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// Snapshot is an immutable, content-addressed collection of evidence observations
// for a specific package version. Its stable ID is a SHA-256 hash of its canonical content,
// ensuring decisions can be audited and reproduced deterministically.
type Snapshot struct {
	id             string
	pkg            string
	version        string
	observations   []verdict.Signal
	providerStates map[string]State
	createdAt      time.Time
}

// canonicalObservation represents the normalized JSON structure used for content hashing.
type canonicalObservation struct {
	Kind        string `json:"kind"`
	Source      string `json:"source"`
	Observation string `json:"observation"`
	Confidence  string `json:"confidence"`
	RetrievedAt string `json:"retrieved_at"`
	FreshUntil  string `json:"fresh_until"`
}

// canonicalState represents a normalized key-value pair for provider outcome states.
type canonicalState struct {
	Key   string `json:"key"`
	State string `json:"state"`
}

type canonicalPayload struct {
	Package        string                 `json:"package"`
	Version        string                 `json:"version"`
	Observations   []canonicalObservation `json:"observations"`
	ProviderStates []canonicalState       `json:"provider_states,omitempty"`
}

// NewSnapshot constructs an immutable Snapshot with a reproducible content-hashed identity.
// Observations are canonicalized and sorted deterministically, ensuring that observations
// collected in any order produce the exact same stable identity.
func NewSnapshot(pkg, version string, observations []verdict.Signal, states map[string]State, createdAt time.Time) Snapshot {
	sortedObs := canonicalizeObservations(observations)
	copiedStates := make(map[string]State, len(states))
	for k, v := range states {
		copiedStates[k] = v
	}

	id := computeSnapshotID(pkg, version, sortedObs, copiedStates)

	return Snapshot{
		id:             id,
		pkg:            pkg,
		version:        version,
		observations:   sortedObs,
		providerStates: copiedStates,
		createdAt:      normalizeTime(createdAt),
	}
}

// ID returns the immutable content-hash identity of the snapshot.
func (s Snapshot) ID() string {
	return s.id
}

// Package returns the package name coordinates.
func (s Snapshot) Package() string {
	return s.pkg
}

// Version returns the package version coordinates.
func (s Snapshot) Version() string {
	return s.version
}

// Observations returns a defensive copy of all observations in canonical order.
func (s Snapshot) Observations() []verdict.Signal {
	res := make([]verdict.Signal, len(s.observations))
	copy(res, s.observations)
	return res
}

// Observation returns the first observation matching the specified kind, if present.
func (s Snapshot) Observation(kind string) (verdict.Signal, bool) {
	for _, obs := range s.observations {
		if obs.Kind == kind {
			return obs, true
		}
	}
	return verdict.Signal{}, false
}

// ObservationsByKind returns all observations matching the specified kind.
func (s Snapshot) ObservationsByKind(kind string) []verdict.Signal {
	var res []verdict.Signal
	for _, obs := range s.observations {
		if obs.Kind == kind {
			res = append(res, obs)
		}
	}
	return res
}

// ProviderStates returns a defensive copy of provider outcome states.
func (s Snapshot) ProviderStates() map[string]State {
	res := make(map[string]State, len(s.providerStates))
	for k, v := range s.providerStates {
		res[k] = v
	}
	return res
}

// State returns the recorded outcome state for a given provider or evidence kind.
func (s Snapshot) State(key string) State {
	if state, ok := s.providerStates[key]; ok {
		return state
	}
	// Fall back to inspecting observations for an explicit unavailable record
	for _, obs := range s.observations {
		if obs.Kind == key && obs.Observation == "unavailable" {
			return StateUnavailable
		}
	}
	return StateAvailable
}

// HasUnavailableEvidence reports whether any provider or evidence kind was unavailable.
func (s Snapshot) HasUnavailableEvidence() bool {
	for _, state := range s.providerStates {
		if state == StateUnavailable {
			return true
		}
	}
	for _, obs := range s.observations {
		if obs.Kind == KindAvailability && obs.Observation == "unavailable" {
			return true
		}
		if obs.Observation == "unavailable" {
			return true
		}
	}
	return false
}

// CreatedAt returns the timestamp when this snapshot was assembled.
func (s Snapshot) CreatedAt() time.Time {
	return s.createdAt
}

type snapshotJSON struct {
	ID             string           `json:"id"`
	Package        string           `json:"package"`
	Version        string           `json:"version"`
	Observations   []verdict.Signal `json:"observations"`
	ProviderStates map[string]State `json:"provider_states,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
}

// MarshalJSON serializes the snapshot into JSON including its stable ID.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(snapshotJSON{
		ID:             s.id,
		Package:        s.pkg,
		Version:        s.version,
		Observations:   s.observations,
		ProviderStates: s.providerStates,
		CreatedAt:      s.createdAt,
	})
}

// UnmarshalJSON deserializes a snapshot from JSON and validates its content hash.
func (s *Snapshot) UnmarshalJSON(data []byte) error {
	var raw snapshotJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	sortedObs := canonicalizeObservations(raw.Observations)
	copiedStates := make(map[string]State, len(raw.ProviderStates))
	for k, v := range raw.ProviderStates {
		copiedStates[k] = v
	}

	computedID := computeSnapshotID(raw.Package, raw.Version, sortedObs, copiedStates)
	if raw.ID != "" && raw.ID != computedID {
		return fmt.Errorf("snapshot identity mismatch: computed %s, stored %s", computedID, raw.ID)
	}

	s.id = computedID
	s.pkg = raw.Package
	s.version = raw.Version
	s.observations = sortedObs
	s.providerStates = copiedStates
	s.createdAt = normalizeTime(raw.CreatedAt)
	return nil
}

func canonicalizeObservations(observations []verdict.Signal) []verdict.Signal {
	res := make([]verdict.Signal, len(observations))
	for i, obs := range observations {
		res[i] = verdict.Signal{
			Kind:        obs.Kind,
			Source:      obs.Source,
			Observation: obs.Observation,
			Confidence:  obs.Confidence,
			RetrievedAt: normalizeTime(obs.RetrievedAt),
			FreshUntil:  normalizeTime(obs.FreshUntil),
		}
	}

	sort.Slice(res, func(i, j int) bool {
		a, b := res[i], res[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Observation != b.Observation {
			return a.Observation < b.Observation
		}
		if a.Confidence != b.Confidence {
			return a.Confidence < b.Confidence
		}
		aRet := a.RetrievedAt.Format(time.RFC3339Nano)
		bRet := b.RetrievedAt.Format(time.RFC3339Nano)
		if aRet != bRet {
			return aRet < bRet
		}
		aFresh := a.FreshUntil.Format(time.RFC3339Nano)
		bFresh := b.FreshUntil.Format(time.RFC3339Nano)
		return aFresh < bFresh
	})

	return res
}

func computeSnapshotID(pkg, version string, sortedObs []verdict.Signal, states map[string]State) string {
	canObs := make([]canonicalObservation, len(sortedObs))
	for i, obs := range sortedObs {
		canObs[i] = canonicalObservation{
			Kind:        obs.Kind,
			Source:      obs.Source,
			Observation: obs.Observation,
			Confidence:  obs.Confidence,
			RetrievedAt: obs.RetrievedAt.Format(time.RFC3339Nano),
			FreshUntil:  obs.FreshUntil.Format(time.RFC3339Nano),
		}
	}

	keys := make([]string, 0, len(states))
	for k := range states {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	canStates := make([]canonicalState, 0, len(keys))
	for _, k := range keys {
		canStates = append(canStates, canonicalState{
			Key:   k,
			State: string(states[k]),
		})
	}

	payload := canonicalPayload{
		Package:        pkg,
		Version:        version,
		Observations:   canObs,
		ProviderStates: canStates,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		// Canonical payload with strings and structs cannot fail JSON marshaling
		hasher := sha256.New()
		hasher.Write([]byte(strings.Join([]string{pkg, version}, ":")))
		return fmt.Sprintf("sha256:%x", hasher.Sum(nil))
	}

	sum := sha256.Sum256(jsonBytes)
	return fmt.Sprintf("sha256:%x", sum)
}
