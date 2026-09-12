package main

import (
	"fmt"
	"os"
	"runtime"
)

const version = "dev"

func main() {
	if len(os.Args) != 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("installgate %s\n", version)
	case "doctor":
		fmt.Printf("InstallGate foundation: OK\nGo: %s\nPlatform: %s/%s\nRegistry gateway: planned for v1.0\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: installgate <version|doctor>")
}
