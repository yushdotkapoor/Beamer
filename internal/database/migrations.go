package database

import (
	"database/sql"
	"fmt"
	"log/slog"
)

var migrations = []struct {
	version int
	sql     string
}{
	{
		version: 1,
		sql: `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    totp_secret   TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash     TEXT    NOT NULL UNIQUE,
    expires_at     TEXT    NOT NULL,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    revoked        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);

CREATE TABLE IF NOT EXISTS media (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path    TEXT    NOT NULL UNIQUE,
    file_name    TEXT    NOT NULL,
    media_type   TEXT    NOT NULL,
    mime_type    TEXT    NOT NULL,
    file_size    INTEGER NOT NULL,
    duration_sec REAL,
    width        INTEGER,
    height       INTEGER,
    parent_dir   TEXT    NOT NULL,
    checksum     TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_media_type   ON media(media_type);
CREATE INDEX IF NOT EXISTS idx_media_parent ON media(parent_dir);
CREATE INDEX IF NOT EXISTS idx_media_name   ON media(file_name);

CREATE VIRTUAL TABLE IF NOT EXISTS media_fts USING fts5(
    file_name,
    content=media,
    content_rowid=id
);

CREATE TRIGGER IF NOT EXISTS media_ai AFTER INSERT ON media BEGIN
    INSERT INTO media_fts(rowid, file_name) VALUES (new.id, new.file_name);
END;
CREATE TRIGGER IF NOT EXISTS media_ad AFTER DELETE ON media BEGIN
    INSERT INTO media_fts(media_fts, rowid, file_name) VALUES('delete', old.id, old.file_name);
END;
CREATE TRIGGER IF NOT EXISTS media_au AFTER UPDATE ON media BEGIN
    INSERT INTO media_fts(media_fts, rowid, file_name) VALUES('delete', old.id, old.file_name);
    INSERT INTO media_fts(rowid, file_name) VALUES (new.id, new.file_name);
END;

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address   TEXT    NOT NULL,
    username     TEXT    NOT NULL,
    success      INTEGER NOT NULL,
    attempted_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_login_ip   ON login_attempts(ip_address, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_user ON login_attempts(username, attempted_at);

CREATE TABLE IF NOT EXISTS server_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`,
	},
}

func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	var current int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}

		slog.Info("running migration", "version", m.version)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("beginning migration %d: %w", m.version, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("executing migration %d: %w", m.version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", m.version); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.version, err)
		}

		slog.Info("migration complete", "version", m.version)
	}

	return nil
}
