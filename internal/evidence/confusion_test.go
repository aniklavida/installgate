package evidence

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestConfusionProviderExactPopularMatch(t *testing.T) {
	corpus := SliceCorpus{"react", "express", "lodash", "axios"}
	p := NewConfusionProvider(
		WithConfusionCorpus(corpus),
		WithConfusionClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "react", Version: "18.2.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	if len(sigs) != 1 || sigs[0].Observation != "exact_popular_match" {
		t.Fatalf("expected exact_popular_match, got %+v", sigs)
	}
}

func TestConfusionProviderKeyboardAdjacencyMatch(t *testing.T) {
	corpus := SliceCorpus{"express", "request", "lodash"}
	p := NewConfusionProvider(
		WithConfusionCorpus(corpus),
		WithConfusionClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	// 'w' is adjacent to 'e' on QWERTY -> exprwss vs express
	outcome := p.Provide(context.Background(), Query{Package: "exprwss", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasConfusion, hasTarget, hasReason bool
	for _, s := range sigs {
		if strings.HasPrefix(s.Observation, "confusion_detected:express") {
			hasConfusion = true
		}
		if s.Observation == "target:express" {
			hasTarget = true
		}
		if strings.HasPrefix(s.Observation, "reason:keyboard_adjacency") {
			hasReason = true
		}
	}

	if !hasConfusion || !hasTarget || !hasReason {
		t.Fatalf("expected keyboard adjacency match against express, got %+v", sigs)
	}
}

func TestConfusionProviderTranspositionMatch(t *testing.T) {
	corpus := SliceCorpus{"axios", "lodash"}
	p := NewConfusionProvider(
		WithConfusionCorpus(corpus),
		WithConfusionClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	// 'axois' swaps 'i' and 'o'
	outcome := p.Provide(context.Background(), Query{Package: "axois", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasTarget, hasTransposition bool
	for _, s := range sigs {
		if s.Observation == "target:axios" {
			hasTarget = true
		}
		if strings.HasPrefix(s.Observation, "reason:transposition") {
			hasTransposition = true
		}
	}

	if !hasTarget || !hasTransposition {
		t.Fatalf("expected transposition match against axios, got %+v", sigs)
	}
}

func TestConfusionProviderUnicodeConfusableMatch(t *testing.T) {
	corpus := SliceCorpus{"react", "express"}
	p := NewConfusionProvider(
		WithConfusionCorpus(corpus),
		WithConfusionClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	// "re\u0430ct" contains Cyrillic small letter а (U+0430)
	candidate := "re\u0430ct"
	outcome := p.Provide(context.Background(), Query{Package: candidate, Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasTarget, hasUnicodeReason bool
	for _, s := range sigs {
		if s.Observation == "target:react" {
			hasTarget = true
		}
		if strings.HasPrefix(s.Observation, "reason:unicode_confusable") {
			hasUnicodeReason = true
		}
	}

	if !hasTarget || !hasUnicodeReason {
		t.Fatalf("expected Unicode confusable match against react, got %+v", sigs)
	}
}

func TestConfusionProviderEditDistanceMatch(t *testing.T) {
	corpus := SliceCorpus{"express", "request"}
	p := NewConfusionProvider(
		WithConfusionCorpus(corpus),
		WithConfusionClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	// "expres" is 1 deletion away from "express"
	outcome := p.Provide(context.Background(), Query{Package: "expres", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasTarget, hasEditReason bool
	for _, s := range sigs {
		if s.Observation == "target:express" {
			hasTarget = true
		}
		if strings.HasPrefix(s.Observation, "reason:edit_distance") {
			hasEditReason = true
		}
	}

	if !hasTarget || !hasEditReason {
		t.Fatalf("expected edit distance match against express, got %+v", sigs)
	}
}

func TestConfusionProviderScopedConfusionMatch(t *testing.T) {
	corpus := SliceCorpus{"react", "express"}
	p := NewConfusionProvider(
		WithConfusionCorpus(corpus),
		WithConfusionClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "@evil-attacker/react", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasTarget, hasScopeReason bool
	for _, s := range sigs {
		if s.Observation == "target:react" {
			hasTarget = true
		}
		if strings.HasPrefix(s.Observation, "reason:scope_confusion") {
			hasScopeReason = true
		}
	}

	if !hasTarget || !hasScopeReason {
		t.Fatalf("expected scope confusion match against react, got %+v", sigs)
	}
}

func TestConfusionProviderCleanPackageNoConfusion(t *testing.T) {
	corpus := SliceCorpus{"react", "express", "lodash"}
	p := NewConfusionProvider(
		WithConfusionCorpus(corpus),
		WithConfusionClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "super-unique-tooling-utility", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	if len(sigs) != 1 || sigs[0].Observation != "no_confusion_detected" {
		t.Fatalf("expected no_confusion_detected, got %+v", sigs)
	}
}

func TestConfusionProviderUnavailableEmptyCorpus(t *testing.T) {
	p := NewConfusionProvider(
		WithConfusionCorpus(nil), // nil corpus
	)

	outcome := p.Provide(context.Background(), Query{Package: "react", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on nil corpus, got %v", outcome.State())
	}
}
