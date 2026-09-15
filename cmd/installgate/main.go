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
	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/gateway"
	"github.com/aniklavida/installgate/internal/mcpserver"
	"github.com/aniklavida/installgate/internal/policy"
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
		runStop(os.Args[2:])
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
	case "check":
		runCheck(os.Args[2:])
	case "explain":
		runExplain(os.Args[2:])
	case "approve":
		runApprove(os.Args[2:])
	case "deny":
		runDeny(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
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
	case "mcp":
		runMCP(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func runInit(args []string) {
	var dryRun bool
	for _, arg := range args {
		if arg == "--dry-run" {
			dryRun = true
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate init [--dry-run]")
			os.Exit(2)
		}
	}

	dataDir := getDataDir()
	if dryRun {
		fmt.Printf("[dry-run] Would initialize InstallGate at %s\n", dataDir)
		fmt.Println("[dry-run] Would initialize SQLite store and database migrations")
		return
	}

	mgr, err := config.NewLifecycleManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	if err := mgr.Init(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: init failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("InstallGate initialized at %s\n", dataDir)
}

func runEnable(args []string) {
	var dryRun bool
	var target string
	for _, arg := range args {
		if arg == "--dry-run" {
			dryRun = true
		} else if target == "" {
			target = arg
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate enable npm [--dry-run]")
			os.Exit(2)
		}
	}

	if target != "npm" {
		fmt.Fprintln(os.Stderr, "usage: installgate enable npm [--dry-run]")
		os.Exit(2)
	}

	mgr, err := config.NewLifecycleManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	st, err := mgr.Status(ctx)
	reg := config.DefaultGatewayURL + "/"
	if err == nil && st.GatewayURL != "" {
		reg = st.GatewayURL + "/"
	}

	if dryRun {
		fmt.Printf("[dry-run] Would enable InstallGate for npm: registry -> %s\n", reg)
		fmt.Println("[dry-run] Would preserve prior configuration byte-for-byte in journal.")
		return
	}

	if err := mgr.EnableNpm(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("InstallGate enabled for npm: registry -> %s\nPrior configuration preserved byte-for-byte.\n", reg)
}

func runDisable(args []string) {
	var dryRun bool
	var target string
	for _, arg := range args {
		if arg == "--dry-run" {
			dryRun = true
		} else if target == "" {
			target = arg
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate disable npm [--dry-run]")
			os.Exit(2)
		}
	}

	if target != "npm" {
		fmt.Fprintln(os.Stderr, "usage: installgate disable npm [--dry-run]")
		os.Exit(2)
	}

	if dryRun {
		fmt.Println("[dry-run] Would disable InstallGate for npm.")
		fmt.Println("[dry-run] Would restore prior registry configuration byte-for-byte from journal.")
		return
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
	var jsonOutput, dryRun bool
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
		case "--json":
			jsonOutput = true
		case "--dry-run":
			dryRun = true
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

	// Handle package@version coordinate format
	if strings.Contains(pkg, "@") {
		lastAt := strings.LastIndex(pkg, "@")
		if lastAt > 0 {
			if ver == "*" {
				ver = pkg[lastAt+1:]
			}
			pkg = pkg[:lastAt]
		}
	}

	// Handle decision ID target (e.g. dec_...)
	if strings.HasPrefix(pkg, "dec_") {
		st, err := getStore()
		if err == nil {
			if doc, err := st.GetDecision(context.Background(), pkg); err == nil && doc != nil {
				pkg = doc.Package
				if ver == "*" {
					ver = doc.Version
				}
			}
			_ = st.Close()
		}
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

	now := time.Now().UTC()
	appID := fmt.Sprintf("app_%d", now.UnixNano())
	expiresAt := now.Add(dur)

	if dryRun {
		if jsonOutput {
			res := map[string]any{
				"dry_run":    true,
				"action":     "approve",
				"package":    pkg,
				"version":    ver,
				"verdict":    "allow",
				"reason":     reason,
				"duration":   durationStr,
				"expires_at": expiresAt.Format(time.RFC3339),
				"actor":      actor,
			}
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("[dry-run] Would create approval: %s (%s@%s, expires in %s at %s)\n", appID, pkg, ver, durationStr, expiresAt.Format(time.RFC3339))
			fmt.Printf("[dry-run] Would record reason: %q by %s\n", reason, actor)
			fmt.Println("[dry-run] Would append audit event: approval_created")
		}
		return
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()
	app := &store.Approval{
		ID:        appID,
		Package:   pkg,
		Version:   ver,
		Reason:    reason,
		Actor:     actor,
		CreatedAt: now,
		ExpiresAt: expiresAt,
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

	if jsonOutput {
		res := map[string]any{
			"approval_id": appID,
			"package":     pkg,
			"version":     ver,
			"verdict":     "allow",
			"reason":      reason,
			"duration":    durationStr,
			"expires_at":  app.ExpiresAt.Format(time.RFC3339),
			"actor":       actor,
		}
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Approval created: %s (%s@%s, expires in %s at %s)\n", appID, pkg, ver, durationStr, app.ExpiresAt.Format(time.RFC3339))
}

func approveUsage() {
	fmt.Fprintln(os.Stderr, "usage: installgate approve <package> [--version <ver>] [--reason <reason>] [--duration <dur>] [--dry-run] [--json]")
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
	var dryRun bool
	var approvalID string

	for _, arg := range args {
		if arg == "--dry-run" {
			dryRun = true
		} else if approvalID == "" {
			approvalID = arg
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate revoke <approval-id> [--dry-run]")
			os.Exit(2)
		}
	}

	if approvalID == "" {
		fmt.Fprintln(os.Stderr, "usage: installgate revoke <approval-id> [--dry-run]")
		os.Exit(2)
	}

	if dryRun {
		fmt.Printf("[dry-run] Would revoke approval: %s\n", approvalID)
		fmt.Println("[dry-run] Would append audit event: approval_revoked")
		return
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.RevokeApproval(ctx, approvalID, now); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: %v\n", err)
		os.Exit(1)
	}

	_ = st.AppendAudit(ctx, &store.AuditEvent{
		EventTime: now,
		EventType: "approval_revoked",
		Metadata: map[string]string{
			"approval_id": approvalID,
		},
	})

	fmt.Printf("Approval %s revoked.\n", approvalID)
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

func runCheck(args []string) {
	var pkg, ver string
	var jsonOutput bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--version", "-v":
			if i+1 < len(args) {
				ver = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		default:
			if !strings.HasPrefix(args[i], "-") && pkg == "" {
				pkg = args[i]
			} else {
				checkUsage()
				os.Exit(2)
			}
		}
	}

	if pkg == "" {
		checkUsage()
		os.Exit(2)
	}

	if strings.Contains(pkg, "@") {
		lastAt := strings.LastIndex(pkg, "@")
		if lastAt > 0 {
			if ver == "" {
				ver = pkg[lastAt+1:]
			}
			pkg = pkg[:lastAt]
		}
	}

	if ver == "" {
		ver = "latest"
	}

	pol, err := policy.LoadDefaultPolicy(".")
	if err != nil || pol == nil {
		pol = policy.NewDefaultPolicy()
	}

	cache := evidence.NewMemoryCache()
	assembler := evidence.NewAssembler(
		evidence.WithCache(cache),
		evidence.WithFreshnessPolicy(evidence.DefaultFreshnessPolicy()),
	)

	var dbStore store.Store
	if st, err := getStore(); err == nil {
		dbStore = st
		defer dbStore.Close()
	}

	engine := gateway.NewEngine(gateway.EngineConfig{
		Policy:    pol,
		Assembler: assembler,
		Store:     dbStore,
		Actor:     "cli",
	})

	ctx := context.Background()
	doc, err := engine.Evaluate(ctx, pkg, ver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: check error: %v\n", err)
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

func checkUsage() {
	fmt.Fprintln(os.Stderr, "usage: installgate check <package> [--version <ver>] [--json]")
}

func runDeny(args []string) {
	var pkg, ver, reason string
	var jsonOutput, dryRun bool
	ver = "*"
	reason = "manual human denial"

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
		case "--json":
			jsonOutput = true
		case "--dry-run":
			dryRun = true
		default:
			if !strings.HasPrefix(args[i], "-") && pkg == "" {
				pkg = args[i]
			} else {
				denyUsage()
				os.Exit(2)
			}
		}
	}

	if pkg == "" {
		denyUsage()
		os.Exit(2)
	}

	if strings.Contains(pkg, "@") {
		lastAt := strings.LastIndex(pkg, "@")
		if lastAt > 0 {
			if ver == "*" {
				ver = pkg[lastAt+1:]
			}
			pkg = pkg[:lastAt]
		}
	}

	if strings.HasPrefix(pkg, "dec_") {
		st, err := getStore()
		if err == nil {
			if doc, err := st.GetDecision(context.Background(), pkg); err == nil && doc != nil {
				pkg = doc.Package
				if ver == "*" {
					ver = doc.Version
				}
			}
			_ = st.Close()
		}
	}

	actor := os.Getenv("USER")
	if actor == "" {
		actor = "operator"
	}
	now := time.Now().UTC()

	if dryRun {
		if jsonOutput {
			res := map[string]any{
				"dry_run":   true,
				"action":    "deny",
				"package":   pkg,
				"version":   ver,
				"verdict":   "block",
				"reason":    reason,
				"actor":     actor,
				"denied_at": now.Format(time.RFC3339),
			}
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("[dry-run] Would record denial: %s@%s (%s) by %s\n", pkg, ver, reason, actor)
			fmt.Println("[dry-run] Would revoke any active approvals for this package")
			fmt.Println("[dry-run] Would append audit event: decision_denied")
		}
		return
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx := context.Background()

	apps, err := st.ListApprovals(ctx, true, now)
	revokedCount := 0
	if err == nil {
		for _, app := range apps {
			if app.Package == pkg && (app.Version == ver || ver == "*" || app.Version == "*") {
				_ = st.RevokeApproval(ctx, app.ID, now)
				revokedCount++
			}
		}
	}

	_ = st.AppendAudit(ctx, &store.AuditEvent{
		EventTime: now,
		EventType: "decision_denied",
		Package:   pkg,
		Version:   ver,
		Actor:     actor,
		Verdict:   string(verdict.Block),
		Metadata: map[string]string{
			"reason":            reason,
			"revoked_approvals": strconv.Itoa(revokedCount),
		},
	})

	if jsonOutput {
		res := map[string]any{
			"action":            "deny",
			"package":           pkg,
			"version":           ver,
			"verdict":           "block",
			"reason":            reason,
			"actor":             actor,
			"revoked_approvals": revokedCount,
			"denied_at":         now.Format(time.RFC3339),
		}
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Denial recorded: %s@%s (%s) by %s\n", pkg, ver, reason, actor)
	if revokedCount > 0 {
		fmt.Printf("Revoked %d active approval(s) for %s@%s.\n", revokedCount, pkg, ver)
	}
}

func denyUsage() {
	fmt.Fprintln(os.Stderr, "usage: installgate deny <package> [--version <ver>] [--reason <reason>] [--dry-run] [--json]")
}

func runPolicy(args []string) {
	var jsonOutput bool
	var subcmd, targetFile string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOutput = true
		default:
			if subcmd == "" {
				subcmd = args[i]
			} else if targetFile == "" {
				targetFile = args[i]
			} else {
				policyUsage()
				os.Exit(2)
			}
		}
	}

	switch subcmd {
	case "bounds":
		if jsonOutput {
			res := map[string]string{
				"bounds": policy.BoundsStatement,
			}
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Println(policy.BoundsStatement)
		}
		return

	case "validate":
		path := targetFile
		if path == "" {
			path = policy.DefaultPolicyFileName
		}
		p, err := policy.LoadPolicyFile(path)
		if err != nil {
			if jsonOutput {
				res := map[string]any{
					"valid": false,
					"file":  path,
					"error": err.Error(),
				}
				data, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Fprintf(os.Stderr, "installgate: policy validation failed for %s: %v\n", path, err)
			}
			os.Exit(1)
		}

		if jsonOutput {
			res := map[string]any{
				"valid":                   true,
				"file":                    path,
				"version":                 p.Version,
				"profile":                 p.Profile,
				"vulnerability_threshold": p.VulnerabilityThreshold,
			}
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Policy %s is valid (profile: %s, vulnerability_threshold: %s)\n", path, p.Profile, p.VulnerabilityThreshold)
		}
		return

	case "", "show":
		pol, err := policy.LoadDefaultPolicy(".")
		if err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed to load policy: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			res := map[string]any{
				"version":                 pol.Version,
				"profile":                 pol.Profile,
				"vulnerability_threshold": pol.VulnerabilityThreshold,
				"bounds":                  pol.BoundsStatement(),
			}
			data, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Println("InstallGate Policy:")
		fmt.Printf("  Version:                 %s\n", pol.Version)
		fmt.Printf("  Profile:                 %s\n", pol.Profile)
		fmt.Printf("  Vulnerability threshold: %s\n", pol.VulnerabilityThreshold)
		fmt.Println("\nPolicy Bounds:")
		for _, line := range strings.Split(pol.BoundsStatement(), "\n") {
			fmt.Printf("  %s\n", line)
		}

	default:
		policyUsage()
		os.Exit(2)
	}
}

func policyUsage() {
	fmt.Fprintln(os.Stderr, "usage: installgate policy [show|bounds|validate <file>] [--json]")
}

func runBackup(args []string) {
	var dryRun bool
	var dest string
	for _, arg := range args {
		if arg == "--dry-run" {
			dryRun = true
		} else if dest == "" {
			dest = arg
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate backup <destination-file> [--dry-run]")
			os.Exit(2)
		}
	}

	if dest == "" {
		fmt.Fprintln(os.Stderr, "usage: installgate backup <destination-file> [--dry-run]")
		os.Exit(2)
	}

	if dryRun {
		fmt.Printf("[dry-run] Would write database backup to %s\n", dest)
		return
	}

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	if err := st.Backup(context.Background(), dest); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: backup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Database backup written to %s\n", dest)
}

func runRestore(args []string) {
	var dryRun bool
	var src string
	for _, arg := range args {
		if arg == "--dry-run" {
			dryRun = true
		} else if src == "" {
			src = arg
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate restore <source-backup-file> [--dry-run]")
			os.Exit(2)
		}
	}

	if src == "" {
		fmt.Fprintln(os.Stderr, "usage: installgate restore <source-backup-file> [--dry-run]")
		os.Exit(2)
	}

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

	if dryRun {
		fmt.Printf("[dry-run] Would restore database from %s\n", src)
		fmt.Println("[dry-run] Verified source backup database is valid SQLite database")
		return
	}

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
	var dryRun bool
	var subcmd string
	for _, arg := range args {
		if arg == "--dry-run" {
			dryRun = true
		} else if subcmd == "" {
			subcmd = arg
		} else {
			fmt.Fprintln(os.Stderr, "usage: installgate cache <status|clear|rebuild> [--dry-run]")
			os.Exit(2)
		}
	}

	if subcmd == "" {
		fmt.Fprintln(os.Stderr, "usage: installgate cache <status|clear|rebuild> [--dry-run]")
		os.Exit(2)
	}

	switch subcmd {
	case "clear":
		if dryRun {
			fmt.Println("[dry-run] Would clear evidence cache in database")
			return
		}
		st, err := getStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
			os.Exit(1)
		}
		defer st.Close()

		ctx := context.Background()
		if err := st.ClearEvidenceCache(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed clearing cache: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Evidence cache cleared.")
	case "rebuild":
		if dryRun {
			fmt.Println("[dry-run] Would clear and rebuild evidence cache from recorded allow decisions")
			return
		}
		st, err := getStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
			os.Exit(1)
		}
		defer st.Close()

		ctx := context.Background()
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
		fmt.Fprintln(os.Stderr, "usage: installgate cache <status|clear|rebuild> [--dry-run]")
		os.Exit(2)
	}
}

func runMCP(args []string) {
	pol, err := policy.LoadDefaultPolicy(".")
	if err != nil || pol == nil {
		pol = policy.NewDefaultPolicy()
	}

	cache := evidence.NewMemoryCache()
	assembler := evidence.NewAssembler(
		evidence.WithCache(cache),
		evidence.WithFreshnessPolicy(evidence.DefaultFreshnessPolicy()),
	)

	st, err := getStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	engine := gateway.NewEngine(gateway.EngineConfig{
		Policy:    pol,
		Assembler: assembler,
		Store:     st,
		Actor:     "mcp",
	})

	srv := mcpserver.NewServer(st, engine, mcpserver.WithPolicy(pol))
	if err := srv.ServeStdio(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: mcp server error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: installgate <init|start|stop|enable npm|disable npm|status|check|explain|approve|deny|policy|approvals|revoke|audit|backup|restore|cache|version|doctor|mcp>")
}
