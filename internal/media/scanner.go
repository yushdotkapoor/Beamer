package media

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
)

type Scanner struct {
	store *Store
	dirs  []string
}

func NewScanner(store *Store, dirs []string) *Scanner {
	return &Scanner{store: store, dirs: dirs}
}

// FullScan walks all configured directories, indexes new/changed files,
// and removes DB entries for files that no longer exist.
func (s *Scanner) FullScan() {
	slog.Info("starting full media scan", "directories", s.dirs)

	var totalFound int64
	var totalIndexed int64
	validPaths := make(map[string]bool)

	batch := make([]*MediaMeta, 0, 100)

	for _, dir := range s.dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			slog.Warn("skipping directory", "dir", dir, "error", err)
			continue
		}

		absDir, _ := filepath.Abs(dir)
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				slog.Debug("walk error", "path", path, "error", err)
				return nil // skip but continue
			}

			if info.IsDir() {
				// Skip hidden directories, but not the configured root directory itself
				absPath, _ := filepath.Abs(path)
				if absPath != absDir && len(info.Name()) > 1 && info.Name()[0] == '.' {
					return filepath.SkipDir
				}
				return nil
			}

			if !IsMediaFile(path) {
				return nil
			}

			atomic.AddInt64(&totalFound, 1)
			validPaths[path] = true

			// Check if file has changed via checksum
			existingChecksum, err := s.store.GetChecksumByPath(path)
			if err == nil && existingChecksum != "" {
				newChecksum, _ := partialChecksum(path)
				if newChecksum == existingChecksum {
					return nil // unchanged
				}
			}

			meta, err := ExtractMetadata(path)
			if err != nil {
				slog.Debug("metadata extraction failed", "path", path, "error", err)
				return nil
			}

			batch = append(batch, meta)
			atomic.AddInt64(&totalIndexed, 1)

			if len(batch) >= 100 {
				if err := s.store.InsertBatch(batch); err != nil {
					slog.Error("batch insert failed", "error", err)
				}
				batch = batch[:0]
			}

			return nil
		})
	}

	// Flush remaining batch
	if len(batch) > 0 {
		if err := s.store.InsertBatch(batch); err != nil {
			slog.Error("batch insert failed", "error", err)
		}
	}

	// Remove entries for deleted files
	deleted, err := s.store.DeleteMissing(validPaths)
	if err != nil {
		slog.Error("failed to clean deleted files", "error", err)
	}

	total, videos, audio, photos := s.store.Count()
	slog.Info("media scan complete",
		"found", totalFound,
		"indexed", totalIndexed,
		"deleted", deleted,
		"total", total,
		"videos", videos,
		"audio", audio,
		"photos", photos,
	)
}

// ScanFile indexes a single file (used by watcher for new/changed files).
func (s *Scanner) ScanFile(path string) {
	if !IsMediaFile(path) {
		return
	}

	meta, err := ExtractMetadata(path)
	if err != nil {
		slog.Debug("metadata extraction failed", "path", path, "error", err)
		return
	}

	if _, err := s.store.Insert(meta); err != nil {
		slog.Error("failed to index file", "path", path, "error", err)
		return
	}

	slog.Info("indexed file", "path", path, "type", meta.MediaType)
}

// RemoveFile deletes a file's entry from the index.
func (s *Scanner) RemoveFile(path string) {
	if err := s.store.DeleteByPath(path); err != nil {
		slog.Error("failed to remove file from index", "path", path, "error", err)
		return
	}
	slog.Info("removed file from index", "path", path)
}
