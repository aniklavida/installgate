package explanation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

func createSampleDoc(t *testing.T, id, pkg, version string) *DecisionDocument {
	t.Helper()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	snap := evidence.NewSnapshot(pkg, version, nil, nil, now)
	dec := verdict.Decision{
		Verdict: verdict.Block,
		Reasons: []verdict.Reason{
			{RuleID: "core.test-rule", Summary: "test rule summary"},
		},
	}
	doc, err := NewDecisionDocument(pkg, version, dec, snap, WithDecisionID(id), WithReferenceTime(now))
	if err != nil {
		t.Fatalf("failed to create sample doc: %v", err)
	}
	return doc
}

func TestMemoryStore(t *testing.T) {
	ms := NewMemoryStore()
	doc := createSampleDoc(t, "dec_12345678", "pkg-a", "1.0.0")

	if err := ms.Save(doc); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	retrieved, err := ms.Get("dec_12345678")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved.DecisionID != "dec_12345678" || retrieved.Package != "pkg-a" {
		t.Errorf("unexpected retrieved doc: %+v", retrieved)
	}

	_, err = ms.Get("dec_nonexistent")
	if !errors.Is(err, ErrDecisionNotFound) {
		t.Errorf("expected ErrDecisionNotFound, got: %v", err)
	}
}

func TestFileStore(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	doc := createSampleDoc(t, "dec_test87654321", "pkg-b", "2.1.0")

	if err := fs.Save(doc); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	filePath := filepath.Join(tempDir, "dec_test87654321.json")
	stat, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("file does not exist: %v", err)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Errorf("expected file mode 0600, got: %o", stat.Mode().Perm())
	}

	retrieved, err := fs.Get("dec_test87654321")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved.DecisionID != "dec_test87654321" || retrieved.Package != "pkg-b" {
		t.Errorf("unexpected retrieved doc: %+v", retrieved)
	}

	// Traversal attempt rejection
	if err := fs.Save(&DecisionDocument{DecisionID: "../traversal"}); err == nil {
		t.Errorf("expected rejection of traversal decision ID")
	}
	if _, err := fs.Get("../traversal"); err == nil {
		t.Errorf("expected rejection of traversal ID in Get")
	}

	// Missing ID
	_, err = fs.Get("dec_missing")
	if !errors.Is(err, ErrDecisionNotFound) {
		t.Errorf("expected ErrDecisionNotFound, got: %v", err)
	}
}

func TestResolve(t *testing.T) {
	tempDir := t.TempDir()
	fs, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	doc := createSampleDoc(t, "dec_resolved1234", "pkg-c", "3.0.0")
	if err := fs.Save(doc); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Resolve via ID through store
	res1, err := Resolve("dec_resolved1234", fs)
	if err != nil {
		t.Fatalf("Resolve via ID failed: %v", err)
	}
	if res1.DecisionID != "dec_resolved1234" {
		t.Errorf("unexpected resolved ID: %s", res1.DecisionID)
	}

	// Resolve directly from file path
	filePath := filepath.Join(tempDir, "dec_resolved1234.json")
	res2, err := Resolve(filePath, nil)
	if err != nil {
		t.Fatalf("Resolve via file path failed: %v", err)
	}
	if res2.DecisionID != "dec_resolved1234" {
		t.Errorf("unexpected resolved ID from file: %s", res2.DecisionID)
	}

	// Non-existent ID returns error
	_, err = Resolve("dec_unknown", fs)
	if err == nil {
		t.Fatal("expected error resolving nonexistent decision ID, got nil")
	}
}
