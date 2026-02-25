package media

import (
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"
)

type MediaItem struct {
	ID          int64    `json:"id"`
	FilePath    string   `json:"-"`
	FileName    string   `json:"file_name"`
	MediaType   string   `json:"media_type"`
	MimeType    string   `json:"mime_type"`
	FileSize    int64    `json:"file_size"`
	FileSizeH   string   `json:"file_size_human"`
	DurationSec *float64 `json:"duration_sec,omitempty"`
	DurationH   string   `json:"duration_human,omitempty"`
	Width       *int     `json:"width,omitempty"`
	Height      *int     `json:"height,omitempty"`
	ParentDir   string   `json:"parent_dir"`
	StreamURL   string   `json:"stream_url"`
	ThumbnailURL string  `json:"thumbnail_url,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type ListParams struct {
	Type    string
	Dir     string
	Sort    string
	Order   string
	Page    int
	PerPage int
	Query   string // for search
}

type ListResult struct {
	Items      []MediaItem `json:"items"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	Total      int         `json:"total"`
	TotalPages int         `json:"total_pages"`
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Insert(m *MediaMeta) (int64, error) {
	result, err := s.db.Exec(
		`INSERT INTO media (file_path, file_name, media_type, mime_type, file_size, duration_sec, width, height, parent_dir, checksum)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(file_path) DO UPDATE SET
		   file_name=excluded.file_name, media_type=excluded.media_type, mime_type=excluded.mime_type,
		   file_size=excluded.file_size, duration_sec=excluded.duration_sec, width=excluded.width,
		   height=excluded.height, parent_dir=excluded.parent_dir, checksum=excluded.checksum,
		   updated_at=datetime('now')`,
		m.FilePath, m.FileName, m.MediaType, m.MimeType, m.FileSize,
		m.DurationSec, m.Width, m.Height, m.ParentDir, m.Checksum,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) InsertBatch(items []*MediaMeta) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(
		`INSERT INTO media (file_path, file_name, media_type, mime_type, file_size, duration_sec, width, height, parent_dir, checksum)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(file_path) DO UPDATE SET
		   file_name=excluded.file_name, media_type=excluded.media_type, mime_type=excluded.mime_type,
		   file_size=excluded.file_size, duration_sec=excluded.duration_sec, width=excluded.width,
		   height=excluded.height, parent_dir=excluded.parent_dir, checksum=excluded.checksum,
		   updated_at=datetime('now')`,
	)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, m := range items {
		_, err := stmt.Exec(
			m.FilePath, m.FileName, m.MediaType, m.MimeType, m.FileSize,
			m.DurationSec, m.Width, m.Height, m.ParentDir, m.Checksum,
		)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) DeleteByPath(path string) error {
	_, err := s.db.Exec("DELETE FROM media WHERE file_path = ?", path)
	return err
}

func (s *Store) DeleteMissing(validPaths map[string]bool) (int, error) {
	rows, err := s.db.Query("SELECT id, file_path FROM media")
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var toDelete []int64
	for rows.Next() {
		var id int64
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			continue
		}
		if !validPaths[path] {
			toDelete = append(toDelete, id)
		}
	}

	if len(toDelete) == 0 {
		return 0, nil
	}

	placeholders := make([]string, len(toDelete))
	args := make([]interface{}, len(toDelete))
	for i, id := range toDelete {
		placeholders[i] = "?"
		args[i] = id
	}

	_, err = s.db.Exec(
		"DELETE FROM media WHERE id IN ("+strings.Join(placeholders, ",")+")",
		args...,
	)
	return len(toDelete), err
}

func (s *Store) GetByID(id int64) (*MediaItem, error) {
	var item MediaItem
	var durSec sql.NullFloat64
	var width, height sql.NullInt64

	err := s.db.QueryRow(
		`SELECT id, file_path, file_name, media_type, mime_type, file_size, duration_sec, width, height, parent_dir, created_at, updated_at
		 FROM media WHERE id = ?`, id,
	).Scan(&item.ID, &item.FilePath, &item.FileName, &item.MediaType, &item.MimeType,
		&item.FileSize, &durSec, &width, &height, &item.ParentDir, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, err
	}

	if durSec.Valid {
		item.DurationSec = &durSec.Float64
	}
	if width.Valid {
		w := int(width.Int64)
		item.Width = &w
	}
	if height.Valid {
		h := int(height.Int64)
		item.Height = &h
	}

	item.FileSizeH = humanizeBytes(item.FileSize)
	item.DurationH = humanizeDuration(item.DurationSec)
	item.StreamURL = fmt.Sprintf("/api/v1/media/%d/stream", item.ID)
	if item.MediaType == "photo" {
		item.ThumbnailURL = fmt.Sprintf("/api/v1/media/%d/thumbnail", item.ID)
	}

	return &item, nil
}

func (s *Store) GetPathByID(id int64) (string, string, error) {
	var filePath, mimeType string
	err := s.db.QueryRow("SELECT file_path, mime_type FROM media WHERE id = ?", id).Scan(&filePath, &mimeType)
	return filePath, mimeType, err
}

func (s *Store) GetChecksumByPath(path string) (string, error) {
	var checksum sql.NullString
	err := s.db.QueryRow("SELECT checksum FROM media WHERE file_path = ?", path).Scan(&checksum)
	if err != nil {
		return "", err
	}
	if !checksum.Valid {
		return "", nil
	}
	return checksum.String, nil
}

func (s *Store) List(params ListParams) (*ListResult, error) {
	params = normalizeParams(params)

	where, args := buildWhereClause(params)
	orderBy := buildOrderBy(params)

	var total int
	countQuery := "SELECT COUNT(*) FROM media" + where
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	offset := (params.Page - 1) * params.PerPage
	query := "SELECT id, file_path, file_name, media_type, mime_type, file_size, duration_sec, width, height, parent_dir, created_at, updated_at FROM media" +
		where + orderBy + fmt.Sprintf(" LIMIT %d OFFSET %d", params.PerPage, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]MediaItem, 0)
	for rows.Next() {
		item, err := scanMediaRow(rows)
		if err != nil {
			continue
		}
		items = append(items, *item)
	}

	return &ListResult{
		Items:      items,
		Page:       params.Page,
		PerPage:    params.PerPage,
		Total:      total,
		TotalPages: int(math.Ceil(float64(total) / float64(params.PerPage))),
	}, nil
}

func (s *Store) Search(params ListParams) (*ListResult, error) {
	params = normalizeParams(params)

	if params.Query == "" {
		return s.List(params)
	}

	// Quote the query for FTS5 — wrapping in double quotes treats it as a phrase
	// and prevents special characters (hyphens, etc.) from being parsed as operators.
	ftsQuery := `"` + strings.ReplaceAll(params.Query, `"`, `""`) + `"`

	// Count
	countArgs := []interface{}{ftsQuery}
	countWhere := ""
	if params.Type != "" {
		countWhere = " AND m.media_type = ?"
		countArgs = append(countArgs, params.Type)
	}

	var total int
	countQ := "SELECT COUNT(*) FROM media m JOIN media_fts f ON m.id = f.rowid WHERE media_fts MATCH ?" + countWhere
	if err := s.db.QueryRow(countQ, countArgs...).Scan(&total); err != nil {
		return nil, err
	}

	offset := (params.Page - 1) * params.PerPage
	queryArgs := []interface{}{ftsQuery}
	queryWhere := ""
	if params.Type != "" {
		queryWhere = " AND m.media_type = ?"
		queryArgs = append(queryArgs, params.Type)
	}

	query := `SELECT m.id, m.file_path, m.file_name, m.media_type, m.mime_type, m.file_size,
	          m.duration_sec, m.width, m.height, m.parent_dir, m.created_at, m.updated_at
	          FROM media m JOIN media_fts f ON m.id = f.rowid
	          WHERE media_fts MATCH ?` + queryWhere +
		fmt.Sprintf(" ORDER BY rank LIMIT %d OFFSET %d", params.PerPage, offset)

	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]MediaItem, 0)
	for rows.Next() {
		item, err := scanMediaRow(rows)
		if err != nil {
			continue
		}
		items = append(items, *item)
	}

	return &ListResult{
		Items:      items,
		Page:       params.Page,
		PerPage:    params.PerPage,
		Total:      total,
		TotalPages: int(math.Ceil(float64(total) / float64(params.PerPage))),
	}, nil
}

func (s *Store) ListDirectories() ([]string, error) {
	rows, err := s.db.Query("SELECT DISTINCT parent_dir FROM media ORDER BY parent_dir")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dirs []string
	for rows.Next() {
		var dir string
		if err := rows.Scan(&dir); err != nil {
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs, nil
}

func (s *Store) DeleteByID(id int64) (string, error) {
	var filePath string
	err := s.db.QueryRow("SELECT file_path FROM media WHERE id = ?", id).Scan(&filePath)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec("DELETE FROM media WHERE id = ?", id)
	if err != nil {
		return "", err
	}
	return filePath, nil
}

func (s *Store) UpdateFileName(id int64, newPath, newName, newParentDir string) error {
	_, err := s.db.Exec(
		`UPDATE media SET file_path = ?, file_name = ?, parent_dir = ?, updated_at = datetime('now') WHERE id = ?`,
		newPath, newName, newParentDir, id,
	)
	return err
}

func (s *Store) GetByFilePath(path string) (*MediaItem, error) {
	var item MediaItem
	var durSec sql.NullFloat64
	var width, height sql.NullInt64

	err := s.db.QueryRow(
		`SELECT id, file_path, file_name, media_type, mime_type, file_size, duration_sec, width, height, parent_dir, created_at, updated_at
		 FROM media WHERE file_path = ?`, path,
	).Scan(&item.ID, &item.FilePath, &item.FileName, &item.MediaType, &item.MimeType,
		&item.FileSize, &durSec, &width, &height, &item.ParentDir, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, err
	}

	if durSec.Valid {
		item.DurationSec = &durSec.Float64
	}
	if width.Valid {
		w := int(width.Int64)
		item.Width = &w
	}
	if height.Valid {
		h := int(height.Int64)
		item.Height = &h
	}

	item.FileSizeH = humanizeBytes(item.FileSize)
	item.DurationH = humanizeDuration(item.DurationSec)
	item.StreamURL = fmt.Sprintf("/api/v1/media/%d/stream", item.ID)
	if item.MediaType == "photo" {
		item.ThumbnailURL = fmt.Sprintf("/api/v1/media/%d/thumbnail", item.ID)
	}

	return &item, nil
}

func (s *Store) Count() (total, videos, audio, photos int) {
	s.db.QueryRow("SELECT COUNT(*) FROM media").Scan(&total)
	s.db.QueryRow("SELECT COUNT(*) FROM media WHERE media_type = 'video'").Scan(&videos)
	s.db.QueryRow("SELECT COUNT(*) FROM media WHERE media_type = 'audio'").Scan(&audio)
	s.db.QueryRow("SELECT COUNT(*) FROM media WHERE media_type = 'photo'").Scan(&photos)
	return
}

// --- helpers ---

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanMediaRow(row scannable) (*MediaItem, error) {
	var item MediaItem
	var durSec sql.NullFloat64
	var width, height sql.NullInt64

	err := row.Scan(&item.ID, &item.FilePath, &item.FileName, &item.MediaType, &item.MimeType,
		&item.FileSize, &durSec, &width, &height, &item.ParentDir, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, err
	}

	if durSec.Valid {
		item.DurationSec = &durSec.Float64
	}
	if width.Valid {
		w := int(width.Int64)
		item.Width = &w
	}
	if height.Valid {
		h := int(height.Int64)
		item.Height = &h
	}

	item.FileSizeH = humanizeBytes(item.FileSize)
	item.DurationH = humanizeDuration(item.DurationSec)
	item.StreamURL = fmt.Sprintf("/api/v1/media/%d/stream", item.ID)
	if item.MediaType == "photo" {
		item.ThumbnailURL = fmt.Sprintf("/api/v1/media/%d/thumbnail", item.ID)
	}

	return &item, nil
}

func normalizeParams(p ListParams) ListParams {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.PerPage < 1 {
		p.PerPage = 50
	}
	if p.PerPage > 100 {
		p.PerPage = 100
	}
	if p.Sort == "" {
		p.Sort = "name"
	}
	if p.Order == "" {
		p.Order = "asc"
	}
	return p
}

func buildWhereClause(p ListParams) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if p.Type != "" {
		conditions = append(conditions, "media_type = ?")
		args = append(args, p.Type)
	}
	if p.Dir != "" {
		conditions = append(conditions, "parent_dir = ?")
		args = append(args, p.Dir)
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

func buildOrderBy(p ListParams) string {
	col := "file_name"
	switch p.Sort {
	case "size":
		col = "file_size"
	case "created":
		col = "created_at"
	case "type":
		col = "media_type"
	}

	dir := "ASC"
	if strings.EqualFold(p.Order, "desc") {
		dir = "DESC"
	}

	return fmt.Sprintf(" ORDER BY %s %s", col, dir)
}

func humanizeBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanizeDuration(sec *float64) string {
	if sec == nil {
		return ""
	}
	d := time.Duration(*sec * float64(time.Second))
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}
