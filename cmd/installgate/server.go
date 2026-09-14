package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aniklavida/installgate/internal/config"
	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/gateway"
	"github.com/aniklavida/installgate/internal/policy"
)

func runStart(args []string) {
	var (
		foreground bool
		port       = config.DefaultGatewayPort
		upstream   = gateway.DefaultUpstreamURL
	)

	// Environment variable overrides
	if envPort := os.Getenv("INSTALLGATE_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			port = p
		}
	}
	if envUpstream := os.Getenv("INSTALLGATE_UPSTREAM_URL"); envUpstream != "" {
		upstream = envUpstream
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--foreground", "-f":
			foreground = true
		case "--port":
			if i+1 >= len(args) {
				startUsage()
				os.Exit(2)
			}
			i++
			p, err := strconv.Atoi(args[i])
			if err != nil || p <= 0 {
				fmt.Fprintf(os.Stderr, "installgate: invalid port %q\n", args[i])
				os.Exit(2)
			}
			port = p
		case "--upstream":
			if i+1 >= len(args) {
				startUsage()
				os.Exit(2)
			}
			i++
			upstream = args[i]
		default:
			startUsage()
			os.Exit(2)
		}
	}

	dataDir := getDataDir()

	if foreground {
		runServerForeground(port, upstream, dataDir)
		return
	}

	// Daemon start
	runServerDaemon(port, upstream, dataDir)
}

func runServerForeground(port int, upstream, dataDir string) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to create data directory: %v\n", err)
		os.Exit(1)
	}

	pidFile := filepath.Join(dataDir, "installgate.pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n%d\n", os.Getpid(), port)), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to write PID file: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = os.Remove(pidFile)
	}()

	cache := evidence.NewMemoryCache()
	store := explanation.DefaultStore()

	// Load repository-local policy if present; otherwise default balanced policy
	pol, err := policy.LoadDefaultPolicy(".")
	if err != nil || pol == nil {
		pol = policy.NewDefaultPolicy()
	}

	assembler := evidence.NewAssembler(
		evidence.WithCache(cache),
		evidence.WithFreshnessPolicy(evidence.DefaultFreshnessPolicy()),
	)

	evaluator := gateway.EvaluatorFunc(func(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error) {
		snap, err := assembler.Assemble(ctx, pkg, version)
		if err != nil {
			return nil, err
		}
		dec := pol.EvaluateSnapshot(snap)
		return explanation.NewDecisionDocument(pkg, version, dec, snap)
	})

	handler, err := gateway.NewHandler(gateway.Config{
		UpstreamBaseURL: upstream,
		Evaluator:       evaluator,
		DecisionStore:   store,
		Cache:           cache,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to initialize gateway handler: %v\n", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to bind %s: %v\n", addr, err)
		os.Exit(1)
	}

	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = os.Remove(pidFile)
	}()

	fmt.Printf("InstallGate gateway running on http://%s\n", addr)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "installgate: server error: %v\n", err)
		os.Exit(1)
	}
}

func runServerDaemon(port int, upstream, dataDir string) {
	// Check if already running
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/-/installgate/health", port)
	client := &http.Client{Timeout: 1 * time.Second}
	if resp, err := client.Get(healthURL); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			fmt.Printf("InstallGate gateway is already running on http://127.0.0.1:%d\n", port)
			return
		}
	}

	binPath, err := os.Executable()
	if err != nil {
		binPath = os.Args[0]
	}

	cmd := exec.Command(binPath, "start", "--foreground", "--port", strconv.Itoa(port), "--upstream", upstream)
	cmd.Env = os.Environ()
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "installgate: failed to start background process: %v\n", err)
		os.Exit(1)
	}

	// Poll health route for readiness up to 5 seconds
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		resp, err := client.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
	}

	if !ready {
		fmt.Fprintf(os.Stderr, "installgate: gateway failed to reach ready state within 5 seconds\n")
		os.Exit(1)
	}

	fmt.Printf("InstallGate gateway started on http://127.0.0.1:%d (pid %d)\n", port, cmd.Process.Pid)
}

func runStop() {
	dataDir := getDataDir()
	pidFile := filepath.Join(dataDir, "installgate.pid")

	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "installgate: gateway is not running (no PID file)")
		os.Exit(1)
	}

	var pid int
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 0 {
		pid, _ = strconv.Atoi(lines[0])
	}

	if pid <= 0 {
		_ = os.Remove(pidFile)
		fmt.Fprintln(os.Stderr, "installgate: invalid PID file, removed")
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		_ = os.Remove(pidFile)
		fmt.Fprintf(os.Stderr, "installgate: process %d not found\n", pid)
		os.Exit(1)
	}

	_ = proc.Signal(syscall.SIGTERM)

	// Wait up to 5 seconds for process termination
	deadline := time.Now().Add(5 * time.Second)
	stopped := false
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		// On Unix, FindProcess always succeeds; Signal(0) checks if process is alive
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			stopped = true
			break
		}
	}

	if !stopped {
		_ = proc.Kill()
	}

	_ = os.Remove(pidFile)
	fmt.Println("InstallGate gateway stopped")
}

func getDataDir() string {
	if env := os.Getenv("INSTALLGATE_DATA_DIR"); env != "" {
		return env
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".installgate")
	}
	return ".installgate"
}

func startUsage() {
	fmt.Fprintln(os.Stderr, "usage: installgate start [--foreground|-f] [--port <port>] [--upstream <url>]")
}
