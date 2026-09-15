package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

// SQLiteStore implements Store backed by an embedded SQLite database in WAL mode.
type SQLiteStore struct {
	db       *sql.DB
	path     string
	mu       sync.RWMutex
	testHook MidMigrationHook
}

// SQLiteOption provides configuration options for SQLiteStore.
type SQLiteOption func(*SQLiteStore)

// WithMidMigrationHook configures a test hook called mid-migration for crash testing.
func WithMidMigrationHook(hook MidMigrationHook) SQLiteOption {
	return func(s *SQLiteStore) {
		s.testHook = hook
	}
}

// OpenSQLite initializes a SQLite database connection with WAL mode and sensible embedded pragmas.
func OpenSQLite(dbPath string, opts ...SQLiteOption) (*SQLiteStore, error) {
	if dbPath == "" {
		return nil, errors.New("database path cannot be empty")
	}

	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// modernc.org/sqlite driver DSN with WAL mode and pragmas
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", filepath.ToSlash(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Set connection limits suitable for embedded concurrency
	db.SetMaxOpenConns(1)

	// Ensure WAL mode and safety pragmas
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode = WAL;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous = NORMAL;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	store := &SQLiteStore{
		db:   db,
		path: dbPath,
	}
	for _, opt := range opts {
		opt(store)
	}

	return store, nil
}

// Close closes the underlying SQLite database handle.
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// CurrentSchemaVersion queries the highest applied migration version.
func (s *SQLiteStore) CurrentSchemaVersion(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var exists int
	checkSQL := "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
	if err := s.db.QueryRowContext(ctx, checkSQL).Scan(&exists); err != nil {
		return 0, fmt.Errorf("failed checking schema_migrations table: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}

	var maxVer sql.NullInt64
	querySQL := "SELECT MAX(version) FROM schema_migrations"
	if err := s.db.QueryRowContext(ctx, querySQL).Scan(&maxVer); err != nil {
		return 0, fmt.Errorf("failed checking max schema version: %w", err)
	}
	if !maxVer.Valid {
		return 0, nil
	}
	return int(maxVer.Int64), nil
}

// ApplyMigrations brings the database schema up to the latest known migration version.
func (s *SQLiteStore) ApplyMigrations(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := initMigrationTable(ctx, s.db); err != nil {
		return err
	}

	applied, err := getAppliedVersions(ctx, s.db)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		if err := applyMigration(ctx, s.db, m, s.testHook); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Name, err)
		}
	}

	return nil
}

// CreateApproval records an attributable, expiring human approval.
func (s *SQLiteStore) CreateApproval(ctx context.Context, app *Approval) error {
	if app == nil {
		return errors.New("cannot create nil approval")
	}
	if app.ID == "" {
		return errors.New("approval id is required")
	}
	if app.Package == "" {
		return errors.New("approval package is required")
	}
	if app.Reason == "" {
		return errors.New("approval reason is required")
	}
	if app.Actor == "" {
		return errors.New("approval actor is required")
	}
	if isAutomatedActor(app.Actor) {
		return ErrNonHumanActor
	}
	if app.ExpiresAt.IsZero() {
		return errors.New("approval expiry timestamp is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	const insertSQL = `INSERT INTO approvals (id, package, version, reason, actor, created_at, expires_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	var revokedAtVal *time.Time
	if app.RevokedAt != nil {
		t := app.RevokedAt.UTC()
		revokedAtVal = &t
	}

	_, err := s.db.ExecContext(ctx, insertSQL,
		app.ID,
		app.Package,
		app.Version,
		app.Reason,
		app.Actor,
		app.CreatedAt.UTC(),
		app.ExpiresAt.UTC(),
		revokedAtVal,
	)
	if err != nil {
		return fmt.Errorf("failed to insert approval: %w", err)
	}
	return nil
}

// GetApproval retrieves an approval by identifier.
func (s *SQLiteStore) GetApproval(ctx context.Context, id string) (*Approval, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const querySQL = `SELECT id, package, version, reason, actor, created_at, expires_at, revoked_at
		FROM approvals WHERE id = ?`

	var app Approval
	var revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, querySQL, id).Scan(
		&app.ID,
		&app.Package,
		&app.Version,
		&app.Reason,
		&app.Actor,
		&app.CreatedAt,
		&app.ExpiresAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrApprovalNotFound
		}
		return nil, fmt.Errorf("failed to query approval: %w", err)
	}

	if revokedAt.Valid {
		t := revokedAt.Time
		app.RevokedAt = &t
	}

	return &app, nil
}

// FindActiveApproval checks if an unexpired, unrevoked approval covers (pkg, version) at time now.
func (s *SQLiteStore) FindActiveApproval(ctx context.Context, pkg, version string, now time.Time) (*Approval, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const querySQL = `SELECT id, package, version, reason, actor, created_at, expires_at, revoked_at
		FROM approvals
		WHERE package = ? AND expires_at > ? AND revoked_at IS NULL
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, querySQL, pkg, now.UTC())
	if err != nil {
		return nil, false, fmt.Errorf("failed to query active approvals: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var app Approval
		var revokedAt sql.NullTime
		if err := rows.Scan(
			&app.ID,
			&app.Package,
			&app.Version,
			&app.Reason,
			&app.Actor,
			&app.CreatedAt,
			&app.ExpiresAt,
			&revokedAt,
		); err != nil {
			return nil, false, fmt.Errorf("failed to scan approval: %w", err)
		}
		if revokedAt.Valid {
			t := revokedAt.Time
			app.RevokedAt = &t
		}

		if matchApprovalVersion(app.Version, version) {
			return &app, true, nil
		}
	}

	return nil, false, rows.Err()
}

// ListApprovals returns approvals, optionally filtered to only active ones at time now.
func (s *SQLiteStore) ListApprovals(ctx context.Context, activeOnly bool, now time.Time) ([]*Approval, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var querySQL string
	var args []any

	if activeOnly {
		querySQL = `SELECT id, package, version, reason, actor, created_at, expires_at, revoked_at
			FROM approvals
			WHERE expires_at > ? AND revoked_at IS NULL
			ORDER BY created_at DESC`
		args = append(args, now.UTC())
	} else {
		querySQL = `SELECT id, package, version, reason, actor, created_at, expires_at, revoked_at
			FROM approvals
			ORDER BY created_at DESC`
	}

	rows, err := s.db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("failed listing approvals: %w", err)
	}
	defer rows.Close()

	var result []*Approval
	for rows.Next() {
		var app Approval
		var revokedAt sql.NullTime
		if err := rows.Scan(
			&app.ID,
			&app.Package,
			&app.Version,
			&app.Reason,
			&app.Actor,
			&app.CreatedAt,
			&app.ExpiresAt,
			&revokedAt,
		); err != nil {
			return nil, fmt.Errorf("failed scanning approval: %w", err)
		}
		if revokedAt.Valid {
			t := revokedAt.Time
			app.RevokedAt = &t
		}
		result = append(result, &app)
	}

	return result, rows.Err()
}

// RevokeApproval marks an existing approval as revoked.
func (s *SQLiteStore) RevokeApproval(ctx context.Context, id string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	const updateSQL = "UPDATE approvals SET revoked_at = ? WHERE id = ?"
	res, err := s.db.ExecContext(ctx, updateSQL, revokedAt.UTC(), id)
	if err != nil {
		return fmt.Errorf("failed revoking approval: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrApprovalNotFound
	}
	return nil
}

// AppendAudit appends an immutable audit event to the append-only log.
func (s *SQLiteStore) AppendAudit(ctx context.Context, event *AuditEvent) error {
	if event == nil {
		return errors.New("cannot append nil audit event")
	}
	if event.EventType == "" {
		return errors.New("audit event type is required")
	}
	if event.EventTime.IsZero() {
		event.EventTime = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var metaJSON, snapJSON string
	if event.Metadata != nil {
		// Ensure metadata is sanitized
		data, err := json.Marshal(sanitizeMetadata(event.Metadata))
		if err != nil {
			return fmt.Errorf("failed to marshal audit metadata: %w", err)
		}
		metaJSON = string(data)
	}
	if event.Snapshot != nil {
		data, err := json.Marshal(event.Snapshot)
		if err != nil {
			return fmt.Errorf("failed to marshal audit snapshot: %w", err)
		}
		snapJSON = string(data)
	}

	const insertSQL = `INSERT INTO audit_events (
		event_time, event_type, package, version, decision_id, rule_id, verdict, actor, metadata_json, snapshot_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	res, err := s.db.ExecContext(ctx, insertSQL,
		event.EventTime.UTC(),
		event.EventType,
		RedactSensitiveString(event.Package),
		RedactSensitiveString(event.Version),
		event.DecisionID,
		RedactSensitiveString(event.RuleID),
		RedactSensitiveString(event.Verdict),
		RedactSensitiveString(event.Actor),
		metaJSON,
		snapJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit event: %w", err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		event.ID = id
	}
	return nil
}

// ListAuditEvents queries audit log records in forward-order.
func (s *SQLiteStore) ListAuditEvents(ctx context.Context, limit, offset int) ([]*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	const querySQL = `SELECT id, event_time, event_type, package, version, decision_id, rule_id, verdict, actor, metadata_json, snapshot_json
		FROM audit_events
		ORDER BY id ASC
		LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, querySQL, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		ev, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// GetAuditEvent retrieves a specific audit record by ID.
func (s *SQLiteStore) GetAuditEvent(ctx context.Context, id int64) (*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const querySQL = `SELECT id, event_time, event_type, package, version, decision_id, rule_id, verdict, actor, metadata_json, snapshot_json
		FROM audit_events
		WHERE id = ?`

	row := s.db.QueryRowContext(ctx, querySQL, id)
	return scanAuditEvent(row)
}

// FindAuditByDecision finds the audit event associated with a decision ID.
func (s *SQLiteStore) FindAuditByDecision(ctx context.Context, decisionID string) (*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const querySQL = `SELECT id, event_time, event_type, package, version, decision_id, rule_id, verdict, actor, metadata_json, snapshot_json
		FROM audit_events
		WHERE decision_id = ?
		ORDER BY id DESC LIMIT 1`

	row := s.db.QueryRowContext(ctx, querySQL, decisionID)
	return scanAuditEvent(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuditEvent(s rowScanner) (*AuditEvent, error) {
	var ev AuditEvent
	var metaJSON, snapJSON sql.NullString
	var pkg, ver, decID, ruleID, verd, actor sql.NullString

	err := s.Scan(
		&ev.ID,
		&ev.EventTime,
		&ev.EventType,
		&pkg,
		&ver,
		&decID,
		&ruleID,
		&verd,
		&actor,
		&metaJSON,
		&snapJSON,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("audit event not found")
		}
		return nil, fmt.Errorf("failed scanning audit event: %w", err)
	}

	if pkg.Valid {
		ev.Package = pkg.String
	}
	if ver.Valid {
		ev.Version = ver.String
	}
	if decID.Valid {
		ev.DecisionID = decID.String
	}
	if ruleID.Valid {
		ev.RuleID = ruleID.String
	}
	if verd.Valid {
		ev.Verdict = verd.String
	}
	if actor.Valid {
		ev.Actor = actor.String
	}

	if metaJSON.Valid && metaJSON.String != "" {
		_ = json.Unmarshal([]byte(metaJSON.String), &ev.Metadata)
	}
	if snapJSON.Valid && snapJSON.String != "" {
		var snap evidence.Snapshot
		if err := json.Unmarshal([]byte(snapJSON.String), &snap); err == nil {
			ev.Snapshot = &snap
		}
	}

	return &ev, nil
}

// SaveDecision stores an evaluation decision document with full details.
func (s *SQLiteStore) SaveDecision(ctx context.Context, doc *explanation.DecisionDocument) error {
	if doc == nil {
		return errors.New("cannot save nil decision document")
	}
	if doc.DecisionID == "" {
		return errors.New("decision document must have an ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := explanation.RenderJSON(doc)
	if err != nil {
		return fmt.Errorf("failed rendering decision JSON: %w", err)
	}

	ruleID := ""
	reason := ""
	if len(doc.Reasons) > 0 {
		ruleID = doc.Reasons[0].RuleID
		reason = doc.Reasons[0].Summary
	}
	createdAt := time.Now().UTC()
	if len(doc.Reasons) > 0 && len(doc.Reasons[0].Evidence) > 0 && !doc.Reasons[0].Evidence[0].RetrievedAt.IsZero() {
		createdAt = doc.Reasons[0].Evidence[0].RetrievedAt.UTC()
	}

	const insertSQL = `INSERT INTO decisions (
		decision_id, package, version, verdict, reason, rule_id, document_json, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(decision_id) DO UPDATE SET
		document_json = excluded.document_json,
		reason = excluded.reason`

	_, err = s.db.ExecContext(ctx, insertSQL,
		doc.DecisionID,
		doc.Package,
		doc.Version,
		string(doc.Verdict),
		reason,
		ruleID,
		string(data),
		createdAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save decision: %w", err)
	}
	return nil
}

// GetDecision retrieves a stored decision document by ID.
func (s *SQLiteStore) GetDecision(ctx context.Context, decisionID string) (*explanation.DecisionDocument, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const querySQL = "SELECT document_json FROM decisions WHERE decision_id = ?"
	var docJSON string
	err := s.db.QueryRowContext(ctx, querySQL, decisionID).Scan(&docJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, explanation.ErrDecisionNotFound
		}
		return nil, fmt.Errorf("failed retrieving decision: %w", err)
	}

	return explanation.ParseJSON([]byte(docJSON))
}

// Save implements explanation.DecisionStore.
func (s *SQLiteStore) Save(doc *explanation.DecisionDocument) error {
	return s.SaveDecision(context.Background(), doc)
}

// Get implements explanation.DecisionStore.
func (s *SQLiteStore) Get(decisionID string) (*explanation.DecisionDocument, error) {
	return s.GetDecision(context.Background(), decisionID)
}

// RecordConfigHistory appends a durable configuration transaction record.
func (s *SQLiteStore) RecordConfigHistory(ctx context.Context, action, phase, payload string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	const insertSQL = `INSERT INTO config_history (action, phase, payload, created_at)
		VALUES (?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, insertSQL, action, phase, RedactSensitiveString(payload), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed inserting config history: %w", err)
	}
	return nil
}

// ListConfigHistory returns configuration history ordered chronologically.
func (s *SQLiteStore) ListConfigHistory(ctx context.Context, limit int) ([]*ConfigRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	const querySQL = `SELECT id, action, phase, payload, created_at
		FROM config_history ORDER BY id DESC LIMIT ?`

	rows, err := s.db.QueryContext(ctx, querySQL, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying config history: %w", err)
	}
	defer rows.Close()

	var records []*ConfigRecord
	for rows.Next() {
		var rec ConfigRecord
		if err := rows.Scan(&rec.ID, &rec.Action, &rec.Phase, &rec.Payload, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning config history: %w", err)
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// SaveCachedEvidence persists an evidence outcome to the database cache table.
func (s *SQLiteStore) SaveCachedEvidence(ctx context.Context, pkg, version, kind string, outcome evidence.Outcome, staleUntil time.Time) error {
	if outcome.State() == evidence.StateUnavailable {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(outcome)
	if err != nil {
		return fmt.Errorf("failed marshaling outcome: %w", err)
	}

	const insertSQL = `INSERT INTO evidence_cache (
		kind, package, version, outcome_json, retrieved_at, fresh_until, stale_until
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(kind, package, version) DO UPDATE SET
		outcome_json = excluded.outcome_json,
		retrieved_at = excluded.retrieved_at,
		fresh_until = excluded.fresh_until,
		stale_until = excluded.stale_until`

	_, err = s.db.ExecContext(ctx, insertSQL,
		kind,
		pkg,
		version,
		string(data),
		outcome.RetrievedAt().UTC(),
		outcome.FreshUntil().UTC(),
		staleUntil.UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed saving cached evidence: %w", err)
	}
	return nil
}

// GetCachedEvidence retrieves an evidence outcome from the database cache.
func (s *SQLiteStore) GetCachedEvidence(ctx context.Context, kind, pkg, version string, now time.Time) (evidence.Outcome, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const querySQL = `SELECT outcome_json, retrieved_at, fresh_until, stale_until
		FROM evidence_cache WHERE kind = ? AND package = ? AND version = ?`

	var outcomeJSON string
	var retrievedAt, freshUntil, staleUntil time.Time

	err := s.db.QueryRowContext(ctx, querySQL, kind, pkg, version).Scan(
		&outcomeJSON,
		&retrievedAt,
		&freshUntil,
		&staleUntil,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return evidence.Outcome{}, false, nil
		}
		return evidence.Outcome{}, false, fmt.Errorf("failed querying evidence cache: %w", err)
	}

	normNow := now.UTC()
	if normNow.After(staleUntil) {
		return evidence.Outcome{}, false, nil
	}

	var outcome evidence.Outcome
	if err := json.Unmarshal([]byte(outcomeJSON), &outcome); err != nil {
		return evidence.Outcome{}, false, fmt.Errorf("corrupt cached outcome: %w", err)
	}

	return outcome, true, nil
}

// SaveCachedAllow persists an evaluated allow decision.
func (s *SQLiteStore) SaveCachedAllow(ctx context.Context, pkg, version string, d verdict.Decision, snapshotID string, retrievedAt, freshUntil, staleUntil time.Time) error {
	if d.Verdict != verdict.Allow {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	decJSON, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshaling decision: %w", err)
	}

	const insertSQL = `INSERT INTO cached_allows (
		package, version, decision_json, snapshot_id, retrieved_at, fresh_until, stale_until
	) VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(package, version) DO UPDATE SET
		decision_json = excluded.decision_json,
		snapshot_id = excluded.snapshot_id,
		retrieved_at = excluded.retrieved_at,
		fresh_until = excluded.fresh_until,
		stale_until = excluded.stale_until`

	_, err = s.db.ExecContext(ctx, insertSQL,
		pkg,
		version,
		string(decJSON),
		snapshotID,
		retrievedAt.UTC(),
		freshUntil.UTC(),
		staleUntil.UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed saving cached allow: %w", err)
	}
	return nil
}

// GetCachedAllow retrieves a cached allow decision.
func (s *SQLiteStore) GetCachedAllow(ctx context.Context, pkg, version string, now time.Time) (evidence.CachedAllow, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	const querySQL = `SELECT decision_json, snapshot_id, retrieved_at, fresh_until, stale_until
		FROM cached_allows WHERE package = ? AND version = ?`

	var decJSON, snapshotID string
	var retrievedAt, freshUntil, staleUntil time.Time

	err := s.db.QueryRowContext(ctx, querySQL, pkg, version).Scan(
		&decJSON,
		&snapshotID,
		&retrievedAt,
		&freshUntil,
		&staleUntil,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return evidence.CachedAllow{}, false, nil
		}
		return evidence.CachedAllow{}, false, fmt.Errorf("failed querying cached allow: %w", err)
	}

	normNow := now.UTC()
	if normNow.After(staleUntil) {
		return evidence.CachedAllow{}, false, nil
	}

	var d verdict.Decision
	if err := json.Unmarshal([]byte(decJSON), &d); err != nil {
		return evidence.CachedAllow{}, false, fmt.Errorf("corrupt cached allow: %w", err)
	}

	allow := evidence.CachedAllow{
		Decision:    d,
		SnapshotID:  snapshotID,
		RetrievedAt: retrievedAt,
		FreshUntil:  freshUntil,
		StaleUntil:  staleUntil,
	}
	return allow, true, nil
}

// ClearEvidenceCache drops cached evidence and cached allows.
func (s *SQLiteStore) ClearEvidenceCache(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed beginning cache clear transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, "DELETE FROM evidence_cache"); err != nil {
		return fmt.Errorf("failed clearing evidence_cache: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cached_allows"); err != nil {
		return fmt.Errorf("failed clearing cached_allows: %w", err)
	}

	return tx.Commit()
}

// Backup creates a crash-consistent snapshot of the database using SQLite VACUUM INTO.
func (s *SQLiteStore) Backup(ctx context.Context, destPath string) error {
	if destPath == "" {
		return errors.New("destination backup path cannot be empty")
	}

	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("failed creating backup directory: %w", err)
	}

	// Remove target if exists because VACUUM INTO fails if destination already exists
	_ = os.Remove(destPath)

	s.mu.Lock()
	defer s.mu.Unlock()

	// VACUUM INTO with bound parameter:
	const vacuumSQL = "VACUUM INTO ?"
	if _, err := s.db.ExecContext(ctx, vacuumSQL, filepath.ToSlash(destPath)); err != nil {
		return fmt.Errorf("failed creating sqlite backup: %w", err)
	}
	return nil
}

// Vacuum executes SQLite VACUUM to reclaim space.
func (s *SQLiteStore) Vacuum(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("failed executing vacuum: %w", err)
	}
	return nil
}

func isAutomatedActor(actor string) bool {
	lower := strings.ToLower(strings.TrimSpace(actor))
	if lower == "" {
		return true
	}
	return strings.HasPrefix(lower, "mcp") ||
		strings.HasPrefix(lower, "agent") ||
		strings.HasPrefix(lower, "bot") ||
		strings.HasPrefix(lower, "automated") ||
		strings.Contains(lower, "ai") ||
		strings.Contains(lower, "claude") ||
		strings.Contains(lower, "llm")
}

func matchApprovalVersion(pattern, target string) bool {
	pattern = strings.TrimSpace(pattern)
	target = strings.TrimSpace(target)
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == target {
		return true
	}
	// Prefix match like "1." or "^1.0.0" can be supported simply
	if strings.HasPrefix(pattern, "^") {
		prefix := strings.TrimPrefix(pattern, "^")
		parts := strings.Split(prefix, ".")
		if len(parts) > 0 && parts[0] != "" {
			targetParts := strings.Split(target, ".")
			return len(targetParts) > 0 && targetParts[0] == parts[0]
		}
	}
	return false
}

func sanitizeMetadata(m map[string]string) map[string]string {
	sanitized := make(map[string]string, len(m))
	for k, v := range m {
		sanitized[k] = RedactSensitiveString(v)
	}
	return sanitized
}
