package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/aniklavida/installgate/internal/explanation"
)

const version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
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
	fmt.Fprintln(os.Stderr, "usage: installgate <version|doctor|explain>")
}
