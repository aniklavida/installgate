package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/aniklavida/installgate/internal/config"
	"github.com/aniklavida/installgate/internal/explanation"
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: installgate <init|start|stop|enable npm|disable npm|status|version|doctor|explain>")
}
