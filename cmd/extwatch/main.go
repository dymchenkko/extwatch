// Command extwatch monitors the VS Code extensions directory for newly
// installed or updated extensions and inspects each change for suspicious code
// patterns (shelling out, env/credential access, network calls, eval, ...).
//
// It compares the just-changed local version against the previous version from
// the VS Code marketplace, so it can surface what *newly* appeared in an update
// rather than flagging long-standing benign code. HIGH-severity findings raise
// a desktop notification; lower-severity findings print to the terminal.
//
// This is a learning-oriented v0.1: static analysis only, detection-only (it
// never blocks an update), and minified bundles limit pattern visibility.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dymchenkko/extwatch/internal/analyzer"
	"github.com/dymchenkko/extwatch/internal/extension"
	"github.com/dymchenkko/extwatch/internal/fetcher"
	"github.com/dymchenkko/extwatch/internal/notifier"
	"github.com/dymchenkko/extwatch/internal/watcher"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "extwatch: %v\n", err)
		os.Exit(1)
	}
}

// run holds the real program so that main itself stays a thin error-reporting
// shell. Idiomatic Go keeps panics/os.Exit confined to main and returns errors
// everywhere else.
func run() error {
	// --dir lets you point at an alternate extensions directory (handy for
	// testing against a fixture tree). It defaults to ~/.vscode/extensions.
	defaultDir, err := defaultExtensionsDir()
	if err != nil {
		return err
	}
	dir := flag.String("dir", defaultDir, "VS Code extensions directory to watch")
	flag.Parse()

	w, err := watcher.New(*dir)
	if err != nil {
		return err
	}
	defer w.Close()

	// One shared marketplace client (connection reuse) handed to each change.
	market := fetcher.New()

	// Run the fsnotify loop on its own goroutine; if it returns an error we
	// surface it through errCh and shut down.
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run() }()

	// Translate SIGINT/SIGTERM into a clean shutdown so deferred cleanup runs.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case ext := <-w.Events:
			handleChange(market, ext)

		case err := <-errCh:
			return err

		case sig := <-sigCh:
			fmt.Printf("\nextwatch: received %s, shutting down\n", sig)
			return nil
		}
	}
}

// handleChange runs the full pipeline for one detected change: extract the
// local JS, fetch and unpack the previous version from the marketplace, diff
// and score, then report. Errors here are logged but never fatal — a single
// failed lookup shouldn't stop the watcher.
func handleChange(market *fetcher.Client, ext extension.Extension) {
	fmt.Printf("extwatch: change detected -> %s\n", ext)

	// Bound the whole network+IO pipeline so a hung download can't wedge us.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 1. Read the just-installed (current) version's JS + manifest from disk.
	newJS, newManifest, err := fetcher.ExtractLocal(ext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extwatch: %s: read local files: %v\n", ext.ID(), err)
		return
	}

	// 2. Ask the marketplace for the version immediately preceding this one.
	//    On any failure we fall back to a baseline-less full scan (oldJS=nil).
	var oldJS map[string]string
	var oldManifest, prevVersion string
	if versions, err := market.Versions(ctx, ext.ID()); err != nil {
		fmt.Fprintf(os.Stderr, "extwatch: %s: marketplace lookup failed (%v); scanning without baseline\n", ext.ID(), err)
	} else if prev, ok := fetcher.PreviousVersion(versions, ext); !ok {
		fmt.Printf("extwatch: %s: no previous version on marketplace; scanning without baseline\n", ext.ID())
	} else {
		prevVersion = prev.Version
		if js, manifest, err := market.DownloadVSIX(ctx, prev.VSIXURL); err != nil {
			fmt.Fprintf(os.Stderr, "extwatch: %s: fetch previous vsix failed (%v); scanning without baseline\n", ext.ID(), err)
		} else {
			oldJS = js
			oldManifest = manifest
		}
	}

	// 3. Diff + score, then 4. report per the notification policy.
	result := analyzer.Analyze(ext, prevVersion, newJS, oldJS, newManifest, oldManifest)
	notifier.Report(result)
}

// defaultExtensionsDir resolves ~/.vscode/extensions for the current user.
func defaultExtensionsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".vscode", "extensions"), nil
}
