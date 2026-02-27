package media

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	scanner  *Scanner
	watcher  *fsnotify.Watcher
	dirs     []string
	debounce map[string]*time.Timer
	mu       sync.Mutex
	done     chan struct{}
}

func NewWatcher(scanner *Scanner, dirs []string) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		scanner:  scanner,
		watcher:  fw,
		dirs:     dirs,
		debounce: make(map[string]*time.Timer),
		done:     make(chan struct{}),
	}

	return w, nil
}

func (w *Watcher) Start() error {
	// Recursively add all directories
	for _, dir := range w.dirs {
		if err := w.addRecursive(dir); err != nil {
			slog.Warn("failed to watch directory", "dir", dir, "error", err)
		}
	}

	go w.eventLoop()

	slog.Info("file watcher started", "directories", w.dirs)
	return nil
}

func (w *Watcher) Stop() {
	close(w.done)
	w.watcher.Close()
	slog.Info("file watcher stopped")
}

func (w *Watcher) addRecursive(root string) error {
	absRoot, _ := filepath.Abs(root)
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		// Skip hidden directories, but not the configured root directory itself
		absPath, _ := filepath.Abs(path)
		if absPath != absRoot && len(info.Name()) > 1 && info.Name()[0] == '.' {
			return filepath.SkipDir
		}
		return w.watcher.Add(path)
	})
}

func (w *Watcher) eventLoop() {
	for {
		select {
		case <-w.done:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("watcher error", "error", err)
		}
	}
}

func (w *Watcher) handleEvent(event fsnotify.Event) {
	path := event.Name

	// If a new directory was created, watch it
	if event.Has(fsnotify.Create) {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			if err := w.addRecursive(path); err != nil {
				slog.Warn("failed to watch new directory", "dir", path, "error", err)
			}
			return
		}
	}

	// Only process media files
	if !IsMediaFile(path) {
		return
	}

	// Debounce: wait 100ms after last event for this path
	w.mu.Lock()
	if timer, exists := w.debounce[path]; exists {
		timer.Stop()
	}

	op := event.Op
	w.debounce[path] = time.AfterFunc(100*time.Millisecond, func() {
		w.mu.Lock()
		delete(w.debounce, path)
		w.mu.Unlock()

		w.processEvent(path, op)
	})
	w.mu.Unlock()
}

func (w *Watcher) processEvent(path string, op fsnotify.Op) {
	if op.Has(fsnotify.Remove) || op.Has(fsnotify.Rename) {
		w.scanner.RemoveFile(path)
		return
	}

	if op.Has(fsnotify.Create) || op.Has(fsnotify.Write) {
		// Verify file still exists (could have been a temp file)
		if _, err := os.Stat(path); err != nil {
			return
		}
		w.scanner.ScanFile(path)
	}
}
