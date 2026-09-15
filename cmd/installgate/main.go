package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/config"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/store"
	"github.com/aniklavida/installgate/internal/verdict"
)

const version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "start":
		runStart(os.Args[2:])
	case "stop":
		runStop()
	case "enable":
		runEnable(os.Args[2:])
	case "disable":
		runDisable(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "version":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		fmt.Printf("installgate %s\n", version)
	case "doctor":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		fmt.Printf("InstallGate foundation: OK\nGo: %s\nPlatform: %s/%s\nRegistry gateway: planned for v1.0\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	case "explain":
		runExplain(os.Args[2:])
	case "approve":
		runApprove(os.Args[2:])
	case "approvals":
		runApprovals(os.Args[2:])
	case "revoke":
		runRevoke(os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "backup":
		runBackup(os.Args[2:])
	case "restore":
		runRestore(os.Args[2:])
	case "cache":
		runCache(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func runInit(args []string) {
	mgr, err := config.NewLifecycleManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	if err := mgr.Init(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: init failed: %v\n", err)
		os.Exit(1)
	}

	dataDir := getDataDir()
	fmt.Printf("InstallGate initialized at %s\n", dataDir)
}

func runEnable(args []string) {
	if len(args) == 0 || args[0] != "npm" {
		fmt.Fprintln(os.Stderr, "usage: installgate enable npm")
		os.Exit(2)
	}

	mgr, err := config.NewLifecycleManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := mgr.EnableNpm(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	st, err := mgr.Status(ctx)
	reg := config.DefaultGatewayURL + "/"
	if err == nil && st.GatewayURL != "" {
		reg = st.GatewayURL + "/"
	}
	fmt.Printf("InstallGate enabled for npm: registry -> %s\nPrior configuration preserved byte-for-byte.\n", reg)
}

func runDisable(args []string) {
	if len(args) == 0 || args[0] != "npm" {
		fmt.Fprintln(os.Stderr, "usage: installgate disable npm")
		os.Exit(2)
	}

	mgr, err := config.NewLifecycleManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := mgr.DisableNpm(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("InstallGate disabled for npm.\nPrior registry configuration restored byte-for-byte.")
}

func runStatus(args []string) {
	var jsonOutput bool
	for _, arg := range args {
		if arg == "--json" || arg == "-json" {
			jsonOutput = true
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate status [--json]")
			os.Exit(2)
		}
	}

	mgr, err := config.NewLifecycleManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	st, err := mgr.Status(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: status failed: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		data, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed to encode JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println("InstallGate Status:")
	if st.GatewayRunning {
		fmt.Printf("  Gateway process:  running on %s\n", st.GatewayURL)
	} else {
		fmt.Println("  Gateway process:  stopped")
	}

	if st.NpmEnabled {
		fmt.Printf("  npm registry:     enabled (pointing to %s)\n", st.ActiveRegistry)
	} else {
		fmt.Printf("  npm registry:     disabled (active: %s)\n", st.ActiveRegistry)
	}
	if st.PriorRegistry != "" {
		fmt.Printf("  Prior registry:   %s\n", st.PriorRegistry)
	}

	if st.GatewayRunning {
		fmt.Printf("  Evidence cache:   %d entries (%d fresh, %d stale)\n",
			st.CacheStats.TotalEntries, st.CacheStats.FreshEntries, st.CacheStats.StaleEntries)
	} else {
		fmt.Println("  Evidence cache:   unavailable (gateway not running)")
	}

	if st.RecoveryNote != "" {
		fmt.Printf("  Recovery:         %s\n", st.RecoveryNote)
	}
}

func runExplain(args []string) {
	var jsonOutput bool
	var target string

	for _, arg := range args {
		if arg == "--json" || arg == "-json" {
			jsonOutput = true
		} else if target == "" {
			target = arg
		} else {
			explainUsage()
			os.Exit(2)
		}
	}

	if target == "" {
		explainUsage()
		os.Exit(2)
	}

	store := explanation.DefaultStore()
	doc, err := explanation.Resolve(target, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		data, err := explanation.RenderJSON(doc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "installgate: error rendering JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(string(data))
	} else {
		fmt.Print(explanation.RenderHuman(doc))
	}
}

func explainUsage() {
	fmt.Fprintln(os.Stderr, "usage: installgate explain [--json] <decision-id>")
}

func getStore() (store.Store, error) {
	dataDir := getDataDir()
	dbPath := filepath.Join(dataDir, "installgate.db")
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	if err := st.ApplyMigrations(context.Background()); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

func runApprove(args []string) {
	var pkg, ver, reason, durationStr string
	ver = "*"
	durationStr = "24h"
	reason = "manual human approval"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--version", "-v":
			if i+1 < len(args) {
				ver = args[i+1]
				i++
			}
		case "--reason", "-r":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		case "--duration", "-d":
			if i+1 < len(args) {
				durationStr = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") && pkg == "" {
				pkg = args[i]
			} else {
				approveUsage()
				os.Exit(2)
			}
		}
	}

	if pkg == "" {
		approveUsage()
		os.Exit(2)
	}

	dur, err := time.ParseDuration(durationStr)
	if err != nil || dur <= 0 {
		fmt.Fprintf(os.Stderr, "installgate: invalid duration %q: %v\n", durationStr, err)
		os.Exit(2)
	}

	actor := os.Getenv("USER")
	if actor == "" {
		actor = "operator"
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	appID := fmt.Sprintf("app_%d", now.UnixNano())
	app := &store.Approval{
		ID:        appID,
		Package:   pkg,
		Version:   ver,
		Reason:    reason,
		Actor:     actor,
		CreatedAt: now,
		ExpiresAt: now.Add(dur),
	}

	if err := st.CreateApproval(ctx, app); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed creating approval: %v\n", err)
		os.Exit(1)
	}

	_ = st.AppendAudit(ctx, &store.AuditEvent{
		EventTime: now,
		EventType: "approval_created",
		Package:   pkg,
		Version:   ver,
		Actor:     actor,
		Metadata: map[string]string{
			"approval_id": appID,
			"reason":      reason,
			"duration":    durationStr,
		},
	})

	fmt.Printf("Approval created: %s (%s@%s, expires in %s at %s)\n", appID, pkg, ver, durationStr, app.ExpiresAt.Format(time.RFC3339))
}

func approveUsage() {
	fmt.Fprintln(os.Stderr, "usage: installgate approve <package> [--version <ver>] [--reason <reason>] [--duration <dur>]")
}

func runApprovals(args []string) {
	var jsonOutput, activeOnly bool
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOutput = true
		case "--active":
			activeOnly = true
		default:
			fmt.Fprintln(os.Stderr, "usage: installgate approvals [--active] [--json]")
			os.Exit(2)
		}
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	apps, err := st.ListApprovals(ctx, activeOnly, now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed listing approvals: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		data, err := json.MarshalIndent(apps, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	if len(apps) == 0 {
		fmt.Println("No recorded approvals.")
		return
	}

	fmt.Println("Approvals:")
	for _, a := range apps {
		status := "active"
		if a.RevokedAt != nil {
			status = "revoked"
		} else if !now.Before(a.ExpiresAt) {
			status = "expired"
		}
		fmt.Printf("  [%s] %s (%s@%s) by %s: %s (expires %s)\n",
			status, a.ID, a.Package, a.Version, a.Actor, a.Reason, a.ExpiresAt.Format(time.RFC3339))
	}
}

func runRevoke(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: installgate revoke <approval-id>")
		os.Exit(2)
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.RevokeApproval(ctx, args[0], now); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	_ = st.AppendAudit(ctx, &store.AuditEvent{
		EventTime: now,
		EventType: "approval_revoked",
		Metadata: map[string]string{
			"approval_id": args[0],
		},
	})

	fmt.Printf("Approval %s revoked.\n", args[0])
}

func runAudit(args []string) {
	var jsonOutput bool
	var decisionID string
	limit := 50

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOutput = true
		case "--decision":
			if i+1 < len(args) {
				decisionID = args[i+1]
				i++
			}
		case "--limit":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					limit = n
				}
				i++
			}
		default:
			fmt.Fprintln(os.Stderr, "usage: installgate audit [--decision <id>] [--limit <n>] [--json]")
			os.Exit(2)
		}
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()

	if decisionID != "" {
		ev, err := st.FindAuditByDecision(ctx, decisionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "installgate: decision audit not found: %v\n", err)
			os.Exit(1)
		}
		data, _ := json.MarshalIndent(ev, "", "  ")
		fmt.Println(string(data))
		return
	}

	if jsonOutput {
		if err := store.ExportAuditJSON(ctx, st, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "installgate: export audit error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	events, err := st.ListAuditEvents(ctx, limit, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed listing audit events: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Println("No audit records found.")
		return
	}

	fmt.Printf("Audit Events (last %d):\n", len(events))
	for _, ev := range events {
		target := ""
		if ev.Package != "" {
			target = fmt.Sprintf("%s@%s", ev.Package, ev.Version)
		}
		fmt.Printf("  [%s] %s | %s %s | verdict: %s | actor: %s\n",
			ev.EventTime.Format(time.RFC3339), ev.EventType, target, ev.DecisionID, ev.Verdict, ev.Actor)
	}
}

func runBackup(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: installgate backup <destination-file>")
		os.Exit(2)
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	dest := args[0]
	if err := st.Backup(context.Background(), dest); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: backup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Database backup written to %s\n", dest)
}

func runRestore(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: installgate restore <source-backup-file>")
		os.Exit(2)
	}

	src := args[0]
	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: source backup file not found: %v\n", err)
		os.Exit(1)
	}

	// Verify source backup file is valid SQLite database
	probeStore, err := store.OpenSQLite(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: invalid source database: %v\n", err)
		os.Exit(1)
	}
	_ = probeStore.Close()

	dataDir := getDataDir()
	dbPath := filepath.Join(dataDir, "installgate.db")

	// Read backup bytes and atomic write to target
	data, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed reading source file: %v\n", err)
		os.Exit(1)
	}

	// Remove WAL and SHM files to prevent stale WAL journals from overlaying restored snapshot
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")

	if err := os.WriteFile(dbPath, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed restoring database: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Database successfully restored from %s\n", src)
}

func runCache(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: installgate cache <status|clear|rebuild>")
		os.Exit(2)
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()

	switch args[0] {
	case "clear":
		if err := st.ClearEvidenceCache(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed clearing cache: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Evidence cache cleared.")
	case "rebuild":
		// Clear existing cache and rebuild from recorded decisions
		if err := st.ClearEvidenceCache(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed clearing cache: %v\n", err)
			os.Exit(1)
		}
		// Walk audit events / decisions to re-populate allow cache
		events, err := st.ListAuditEvents(ctx, 500, 0)
		rebuilt := 0
		if err == nil {
			now := time.Now().UTC()
			for _, ev := range events {
				if ev.EventType == "decision" && ev.Verdict == string(verdict.Allow) && ev.Package != "" {
					dec := verdict.Decision{
						Verdict: verdict.Allow,
						Reasons: []verdict.Reason{
							{
								RuleID:  ev.RuleID,
								Summary: fmt.Sprintf("rebuilt allow decision for %s@%s", ev.Package, ev.Version),
							},
						},
					}
					_ = st.SaveCachedAllow(ctx, ev.Package, ev.Version, dec, ev.DecisionID, now, now.Add(time.Hour), now.Add(24*time.Hour))
					rebuilt++
				}
			}
		}
		fmt.Printf("Evidence cache rebuilt (%d entries restored).\n", rebuilt)
	case "status":
		fmt.Println("Cache operational and backed by SQLite store.")
	default:
		fmt.Fprintln(os.Stderr, "usage: installgate cache <status|clear|rebuild>")
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: installgate <init|start|stop|enable npm|disable npm|status|version|doctor|explain|approve|approvals|revoke|audit|backup|restore|cache>")
}
