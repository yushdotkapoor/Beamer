package database

import (
	"database/sql"
	"fmt"

	"github.com/yushrajkapoor/beamer/internal/config"

	_ "modernc.org/sqlite"
)

func Open(cfg config.DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Single connection for SQLite — avoids "database is locked" issues.
	// WAL mode allows concurrent readers, but writes must be serialized.
	db.SetMaxOpenConns(1)

	pragmas := []struct {
		name  string
		value interface{}
	}{
		{"journal_mode", cfg.JournalMode},
		{"busy_timeout", cfg.BusyTimeout},
		{"cache_size", cfg.CacheSize},
		{"synchronous", cfg.Synchronous},
		{"foreign_keys", "ON"},
		{"temp_store", "MEMORY"},
	}

	for _, p := range pragmas {
		if _, err := db.Exec(fmt.Sprintf("PRAGMA %s = %v", p.name, p.value)); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting pragma %s: %w", p.name, err)
		}
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return db, nil
}
