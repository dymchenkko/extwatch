// Package watcher observes the VS Code extensions directory and emits a parsed
// extension.Extension whenever an extension is installed or updated, debouncing
// the burst of filesystem events an install produces.
package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dymchenkko/extwatch/internal/extension"
	"github.com/fsnotify/fsnotify"
)

// Watcher observes the VS Code extensions root directory and emits an
// extension.Extension on its Events channel whenever an extension directory is
// created or modified. It debounces bursts of filesystem events (an install
// touches hundreds of files) so each settled change surfaces exactly once.
type Watcher struct {
	root     string
	fsw      *fsnotify.Watcher
	Events   chan extension.Extension
	debounce time.Duration

	// pending tracks the per-extension debounce timers. The mutex guards it
	// because timer callbacks fire on their own goroutines.
	mu      sync.Mutex
	pending map[string]*time.Timer
}

// New creates a Watcher rooted at the given extensions directory. It does not
// start watching until Run is called.
func New(root string) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}
	return &Watcher{
		root:     root,
		fsw:      fsw,
		Events:   make(chan extension.Extension),
		debounce: 2 * time.Second,
		pending:  make(map[string]*time.Timer),
	}, nil
}

// Run starts the watch loop and blocks until shutdown via Close. fsnotify on the
// extensions root is non-recursive: it reports the creation of a new
// "<publisher>.<name>-<version>" directory (the signal VS Code emits on
// install/update) and writes to entries directly inside the root. That is the
// signal we care about — a version bump always materialises as a brand-new
// versioned directory.
func (w *Watcher) Run() error {
	if err := w.fsw.Add(w.root); err != nil {
		return fmt.Errorf("watch %s: %w", w.root, err)
	}
	fmt.Printf("extwatch: watching %s\n", w.root)

	for {
		select {
		case event, ok := <-w.fsw.Events:
			if !ok {
				return nil // channel closed by Close
			}
			// We only care about content appearing or changing. Renames and
			// removes (e.g. the .obsolete bookkeeping VS Code does) are noise.
			if event.Op&(fsnotify.Create|fsnotify.Write) == 0 {
				continue
			}
			w.handle(event.Name)

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return nil
			}
			// Watcher errors are non-fatal; log and keep going.
			fmt.Fprintf(os.Stderr, "extwatch: watch error: %v\n", err)
		}
	}
}

// handle maps a raw filesystem path to the extension directory it belongs to
// and schedules a debounced emit. A path may be the extension directory itself
// (Create of a new install) or a file inside it (Write during an update), so
// we normalise both to the top-level extension directory under root.
func (w *Watcher) handle(path string) {
	dir := w.extensionDirFor(path)
	if dir == "" {
		return
	}
	ext, ok := extension.ParseDir(dir)
	if !ok {
		return
	}
	w.schedule(ext)
}

// extensionDirFor returns the immediate child of root that contains path, or
// "" if path is not under root. This collapses "root/pub.name-1.2.3/out/x.js"
// down to "root/pub.name-1.2.3".
func (w *Watcher) extensionDirFor(path string) string {
	rel, err := filepath.Rel(w.root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	// The first path segment of rel is the extension directory name.
	first := rel
	if i := strings.IndexRune(rel, filepath.Separator); i >= 0 {
		first = rel[:i]
	}
	return filepath.Join(w.root, first)
}

// schedule (re)arms the debounce timer for an extension. Repeated events
// within the debounce window keep pushing the emit back, so we fire only once
// the directory has been quiet for w.debounce.
func (w *Watcher) schedule(ext extension.Extension) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if t, ok := w.pending[ext.Dir]; ok {
		t.Reset(w.debounce)
		return
	}
	w.pending[ext.Dir] = time.AfterFunc(w.debounce, func() {
		w.mu.Lock()
		delete(w.pending, ext.Dir)
		w.mu.Unlock()
		// The directory may have been renamed or removed during the debounce
		// window (transient staging dirs, an aborted install). Don't emit a
		// change for something that no longer exists on disk.
		if _, err := os.Stat(ext.Dir); err != nil {
			return
		}
		w.Events <- ext
	})
}

// Close stops watching and releases OS resources. Pending debounce timers are
// stopped so they don't fire into a closed channel.
func (w *Watcher) Close() error {
	w.mu.Lock()
	for _, t := range w.pending {
		t.Stop()
	}
	w.pending = map[string]*time.Timer{}
	w.mu.Unlock()
	return w.fsw.Close()
}
