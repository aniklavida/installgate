package evidence

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/aniklavida/installgate/internal/verdict"
)

var (
	errEmptyCorpus      = errors.New("name confusion provider: popular package corpus is empty or unavailable")
	errConfusionTimeout = errors.New("name confusion provider: evaluation timed out")
)

// Corpus defines the interface for accessing the popular-package corpus.
// The source of the popular-package corpus is decoupled through this interface
// so future data sources (static lists, SQLite, remote sync) can be swapped in.
type Corpus interface {
	Contains(name string) bool
	All() []string
}

// SliceCorpus is an in-memory slice implementation of Corpus.
type SliceCorpus []string

func (s SliceCorpus) Contains(name string) bool {
	target := strings.ToLower(name)
	for _, p := range s {
		if strings.ToLower(p) == target {
			return true
		}
	}
	return false
}

func (s SliceCorpus) All() []string {
	res := make([]string, len(s))
	copy(res, s)
	return res
}

// ConfusionMatch records a detected confusion match against a popular package.
// It explicitly returns the matched target and the reason for the match,
// never a bare similarity score.
type ConfusionMatch struct {
	Target string
	Reason string
	Score  float64
}

// ConfusionProvider inspects package names for normalized edit distance,
// keyboard-adjacency, and Unicode-confusable similarities against a popular-package corpus.
type ConfusionProvider struct {
	name     string
	corpus   Corpus
	timeout  time.Duration
	clock    func() time.Time
	freshTTL time.Duration
	sem      chan struct{}
}

// ConfusionOption configures a ConfusionProvider.
type ConfusionOption func(*ConfusionProvider)

// WithConfusionCorpus sets the popular-package corpus.
func WithConfusionCorpus(corpus Corpus) ConfusionOption {
	return func(p *ConfusionProvider) {
		p.corpus = corpus
	}
}

// WithConfusionTimeout sets the timeout for confusion evaluation.
func WithConfusionTimeout(timeout time.Duration) ConfusionOption {
	return func(p *ConfusionProvider) {
		if timeout > 0 {
			p.timeout = timeout
		}
	}
}

// WithConfusionClock sets a custom clock function for deterministic testing.
func WithConfusionClock(clock func() time.Time) ConfusionOption {
	return func(p *ConfusionProvider) {
		if clock != nil {
			p.clock = clock
		}
	}
}

// WithConfusionConcurrency limits concurrency for name comparison.
func WithConfusionConcurrency(maxConns int) ConfusionOption {
	return func(p *ConfusionProvider) {
		if maxConns > 0 {
			p.sem = make(chan struct{}, maxConns)
		}
	}
}

// NewConfusionProvider constructs a name confusion evidence provider.
func NewConfusionProvider(opts ...ConfusionOption) *ConfusionProvider {
	p := &ConfusionProvider{
		name:     "name_confusion",
		timeout:  5 * time.Second,
		freshTTL: 12 * time.Hour,
		sem:      make(chan struct{}, DefaultMaxConns),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *ConfusionProvider) Name() string {
	return p.name
}

func (p *ConfusionProvider) Kind() string {
	return KindNameConfusion
}

// Provide evaluates the query package name against the corpus.
func (p *ConfusionProvider) Provide(ctx context.Context, q Query) Outcome {
	now := p.now()

	if p.corpus == nil || len(p.corpus.All()) == 0 {
		return NewUnavailableOutcome(p.Kind(), p.Name(), errEmptyCorpus, now)
	}

	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return NewUnavailableOutcome(p.Kind(), p.Name(), ctx.Err(), now)
	}

	reqCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	match, err := p.evaluateCandidate(reqCtx, q.Package)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}

	freshUntil := now.Add(p.freshTTL)

	// If candidate is an exact legitimate member of the corpus, it is not confusable with itself
	if p.corpus.Contains(q.Package) {
		sigs := []verdict.Signal{
			{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: "exact_popular_match",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		return NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
	}

	if match == nil {
		sigs := []verdict.Signal{
			{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: "no_confusion_detected",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		return NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
	}

	// Match found: return target and reason
	sigs := []verdict.Signal{
		{
			Kind:        p.Kind(),
			Source:      p.Name(),
			Observation: fmt.Sprintf("confusion_detected:%s", match.Target),
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		},
		{
			Kind:        p.Kind(),
			Source:      p.Name(),
			Observation: fmt.Sprintf("target:%s", match.Target),
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		},
		{
			Kind:        p.Kind(),
			Source:      p.Name(),
			Observation: fmt.Sprintf("reason:%s", match.Reason),
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		},
	}

	reasonStr := fmt.Sprintf("confusable with %q: %s", match.Target, match.Reason)
	outcome := NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
	outcome.reason = reasonStr
	return outcome
}

func (p *ConfusionProvider) evaluateCandidate(ctx context.Context, candidate string) (*ConfusionMatch, error) {
	candidateLower := strings.ToLower(candidate)
	popularPackages := p.corpus.All()

	// 1. Check Unicode confusables / homoglyphs first
	if unicodeMatch := checkUnicodeConfusable(candidate, popularPackages); unicodeMatch != nil {
		return unicodeMatch, nil
	}

	// 2. Check scoped imitation: e.g. @evil/react vs react
	if strings.HasPrefix(candidateLower, "@") {
		parts := strings.SplitN(candidateLower, "/", 2)
		if len(parts) == 2 && parts[1] != "" {
			unscoped := parts[1]
			for _, target := range popularPackages {
				targetLower := strings.ToLower(target)
				if unscoped == targetLower {
					return &ConfusionMatch{
						Target: target,
						Reason: fmt.Sprintf("scope_confusion: unscoped package name %q matches popular package %q under untrusted scope %q", unscoped, target, parts[0]),
						Score:  1.0,
					}, nil
				}
			}
		}
	}

	// 3. Normalized comparisons: edit distance, transpositions, and keyboard adjacency
	for _, target := range popularPackages {
		select {
		case <-ctx.Done():
			return nil, errConfusionTimeout
		default:
		}

		targetLower := strings.ToLower(target)
		if candidateLower == targetLower {
			continue // Handled as exact_popular_match
		}

		// Separator normalization: lodash-es vs lodashes, cross-env vs crossenv
		normCand := normalizeSeparators(candidateLower)
		normTarg := normalizeSeparators(targetLower)
		if normCand == normTarg && normCand != "" {
			return &ConfusionMatch{
				Target: target,
				Reason: fmt.Sprintf("normalized_separators: differs only by hyphens or punctuation from popular package %q", target),
				Score:  0.98,
			}, nil
		}

		// Keyboard adjacency check
		if isAdjacent, diffChar, adjChar, idx := checkKeyboardAdjacency(candidateLower, targetLower); isAdjacent {
			return &ConfusionMatch{
				Target: target,
				Reason: fmt.Sprintf("keyboard_adjacency: character %q at index %d is adjacent on QWERTY keyboard to %q in popular package %q", diffChar, idx, adjChar, target),
				Score:  0.95,
			}, nil
		}

		// Transposition check (Damerau-Levenshtein swap of 2 adjacent letters)
		if isTransposition(candidateLower, targetLower) {
			return &ConfusionMatch{
				Target: target,
				Reason: fmt.Sprintf("transposition: adjacent characters transposed compared to popular package %q", target),
				Score:  0.95,
			}, nil
		}

		// Edit distance check
		dist := levenshteinDistance(candidateLower, targetLower)
		maxLen := math.Max(float64(len(candidateLower)), float64(len(targetLower)))
		sim := 1.0 - (float64(dist) / maxLen)

		// Distance 1 match for words of length >= 4 (e.g. expres vs express, reqeust vs request)
		if dist == 1 && len(targetLower) >= 4 {
			return &ConfusionMatch{
				Target: target,
				Reason: fmt.Sprintf("edit_distance: 1 edit away from popular package %q (similarity: %.2f)", target, sim),
				Score:  sim,
			}, nil
		}

		// Distance 2 match for longer names (>= 8 chars) with high normalized similarity >= 0.80
		if dist == 2 && len(targetLower) >= 8 && sim >= 0.80 {
			return &ConfusionMatch{
				Target: target,
				Reason: fmt.Sprintf("edit_distance: 2 edits away from popular package %q (similarity: %.2f)", target, sim),
				Score:  sim,
			}, nil
		}
	}

	return nil, nil
}

// Unicode confusable lookalike mapping
var confusableMap = map[rune]rune{
	// Cyrillic small letters
	'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j', 'о': 'o', 'р': 'p', 'ѕ': 's', 'у': 'y', 'х': 'x',
	'ԛ': 'q', 'ԝ': 'w',
	// Cyrillic capital letters
	'А': 'a', 'В': 'b', 'С': 'c', 'Е': 'e', 'Н': 'h', 'І': 'i', 'Ј': 'j', 'К': 'k', 'М': 'm', 'О': 'o',
	'Р': 'p', 'Ѕ': 's', 'Т': 't', 'Х': 'x',
	// Greek small letters
	'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'υ': 'u', 'ν': 'v', 'χ': 'x',
}

func checkUnicodeConfusable(candidate string, targets []string) *ConfusionMatch {
	hasNonASCII := false
	for _, r := range candidate {
		if r > unicode.MaxASCII {
			hasNonASCII = true
			break
		}
	}
	if !hasNonASCII {
		return nil
	}

	var sb strings.Builder
	for _, r := range candidate {
		if mapped, ok := confusableMap[r]; ok {
			sb.WriteRune(mapped)
		} else {
			sb.WriteRune(unicode.ToLower(r))
		}
	}
	skeleton := sb.String()

	for _, target := range targets {
		if skeleton == strings.ToLower(target) {
			return &ConfusionMatch{
				Target: target,
				Reason: fmt.Sprintf("unicode_confusable: contains lookalike Unicode characters that skeleton-map to popular package %q", target),
				Score:  0.99,
			}
		}
	}

	return nil
}

// QWERTY keyboard adjacency map
var qwertyAdjacent = map[byte]string{
	'q': "was",
	'w': "qeasd",
	'e': "wrsdf",
	'r': "etdfg",
	't': "ryfgh",
	'y': "tughj",
	'u': "yihjk",
	'i': "uojkl",
	'o': "ipkl",
	'p': "ol",
	'a': "qwsz",
	's': "awedxz",
	'd': "serfcx",
	'f': "drtgvc",
	'g': "ftyhbv",
	'h': "gyujnb",
	'j': "huikmn",
	'k': "jiolm",
	'l': "kop",
	'z': "asx",
	'x': "zsdc",
	'c': "xdfv",
	'v': "cfgb",
	'b': "vghn",
	'n': "bhjm",
	'm': "njk",
}

func checkKeyboardAdjacency(candidate, target string) (bool, byte, byte, int) {
	if len(candidate) != len(target) || len(candidate) == 0 {
		return false, 0, 0, 0
	}

	diffCount := 0
	diffIdx := -1

	for i := 0; i < len(candidate); i++ {
		if candidate[i] != target[i] {
			diffCount++
			diffIdx = i
		}
	}

	if diffCount == 1 {
		c1 := candidate[diffIdx]
		c2 := target[diffIdx]
		if adj, ok := qwertyAdjacent[c1]; ok {
			if strings.IndexByte(adj, c2) >= 0 {
				return true, c1, c2, diffIdx
			}
		}
	}

	return false, 0, 0, 0
}

func isTransposition(candidate, target string) bool {
	if len(candidate) != len(target) || len(candidate) < 3 {
		return false
	}

	diffIndices := make([]int, 0, 2)
	for i := 0; i < len(candidate); i++ {
		if candidate[i] != target[i] {
			diffIndices = append(diffIndices, i)
		}
	}

	if len(diffIndices) == 2 && diffIndices[1] == diffIndices[0]+1 {
		i, j := diffIndices[0], diffIndices[1]
		return candidate[i] == target[j] && candidate[j] == target[i]
	}

	return false
}

func normalizeSeparators(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b != '-' && b != '_' && b != '.' {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

func levenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n1, n2 := len(r1), len(r2)

	if n1 == 0 {
		return n2
	}
	if n2 == 0 {
		return n1
	}

	prev := make([]int, n2+1)
	curr := make([]int, n2+1)

	for j := 0; j <= n2; j++ {
		prev[j] = j
	}

	for i := 1; i <= n1; i++ {
		curr[0] = i
		for j := 1; j <= n2; j++ {
			cost := 1
			if r1[i-1] == r2[j-1] {
				cost = 0
			}
			curr[j] = min(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		copy(prev, curr)
	}

	return curr[n2]
}

func (p *ConfusionProvider) now() time.Time {
	if p.clock != nil {
		return normalizeTime(p.clock())
	}
	return normalizeTime(time.Now())
}
