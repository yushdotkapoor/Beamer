package media

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Handler struct {
	store     *Store
	scanner   *Scanner
	uploadDir string
}

func NewHandler(store *Store, scanner *Scanner, uploadDir string) *Handler {
	return &Handler{store: store, scanner: scanner, uploadDir: uploadDir}
}

func (h *Handler) ListMedia(w http.ResponseWriter, r *http.Request) {
	params := parseListParams(r)
	result, err := h.store.List(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to list media")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": result.Items,
		"meta": map[string]interface{}{
			"page":        result.Page,
			"per_page":    result.PerPage,
			"total":       result.Total,
			"total_pages": result.TotalPages,
		},
	})
}

func (h *Handler) GetMedia(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid media ID")
		return
	}

	item, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Media not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": item,
	})
}

func (h *Handler) StreamMedia(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid media ID")
		return
	}

	filePath, mimeType, err := h.store.GetPathByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Media not found")
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "FILE_MISSING", "File no longer exists on disk")
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STAT_ERROR", "Failed to read file")
		return
	}

	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// http.ServeContent handles Range requests, 206 Partial Content,
	// If-Modified-Since, Content-Length — all automatically.
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func (h *Handler) ServeThumbnail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid media ID")
		return
	}

	item, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Media not found")
		return
	}

	if item.MediaType != "photo" {
		writeError(w, http.StatusNotFound, "NO_THUMBNAIL", "Thumbnails only available for photos")
		return
	}

	// Serve original photo as thumbnail (no resizing in Phase 3)
	f, err := os.Open(item.FilePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "FILE_MISSING", "File no longer exists on disk")
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STAT_ERROR", "Failed to read file")
		return
	}

	w.Header().Set("Content-Type", item.MimeType)
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func (h *Handler) BrowseDirectories(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")

	if dir != "" {
		// List media in a specific directory
		params := parseListParams(r)
		params.Dir = dir
		result, err := h.store.List(params)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to browse directory")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": result.Items,
			"meta": map[string]interface{}{
				"page":        result.Page,
				"per_page":    result.PerPage,
				"total":       result.Total,
				"total_pages": result.TotalPages,
				"directory":   dir,
			},
		})
		return
	}

	// List all directories
	dirs, err := h.store.ListDirectories()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to list directories")
		return
	}
	if dirs == nil {
		dirs = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": dirs,
	})
}

func (h *Handler) SearchMedia(w http.ResponseWriter, r *http.Request) {
	params := parseListParams(r)
	params.Query = r.URL.Query().Get("q")

	if params.Query == "" {
		writeError(w, http.StatusBadRequest, "MISSING_QUERY", "Search query 'q' parameter required")
		return
	}

	result, err := h.store.Search(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SEARCH_ERROR", "Search failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": result.Items,
		"meta": map[string]interface{}{
			"page":        result.Page,
			"per_page":    result.PerPage,
			"total":       result.Total,
			"total_pages": result.TotalPages,
			"query":       params.Query,
		},
	})
}

func (h *Handler) TriggerRescan(w http.ResponseWriter, r *http.Request) {
	go h.scanner.FullScan()
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"data": map[string]string{
			"message": "Rescan started in background",
		},
	})
}

func (h *Handler) UploadMedia(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "PARSE_ERROR", "Failed to parse upload")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "No file provided in 'file' field")
		return
	}
	defer file.Close()

	filename := header.Filename
	if !IsMediaFile(filename) {
		writeError(w, http.StatusBadRequest, "UNSUPPORTED_TYPE", "File type not supported")
		return
	}

	destPath := filepath.Join(h.uploadDir, filename)

	// Handle filename conflicts
	if _, err := os.Stat(destPath); err == nil {
		ext := filepath.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		destPath = filepath.Join(h.uploadDir, fmt.Sprintf("%s_%d%s", base, time.Now().UnixNano(), ext))
	}

	dest, err := os.Create(destPath)
	if err != nil {
		slog.Error("failed to create upload file", "path", destPath, "error", err)
		writeError(w, http.StatusInternalServerError, "WRITE_ERROR", "Failed to save file")
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		os.Remove(destPath)
		writeError(w, http.StatusInternalServerError, "WRITE_ERROR", "Failed to write file")
		return
	}

	// Index the file immediately
	h.scanner.ScanFile(destPath)

	item, err := h.store.GetByFilePath(destPath)
	if err != nil {
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"data": map[string]string{
				"message":   "File uploaded successfully",
				"file_name": filepath.Base(destPath),
			},
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"data": item,
	})
}

func (h *Handler) DeleteMedia(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid media ID")
		return
	}

	filePath, err := h.store.DeleteByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Media not found")
		return
	}

	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to delete file from disk", "path", filePath, "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RenameMedia(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid media ID")
		return
	}

	var req struct {
		FileName string `json:"file_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FileName == "" {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "file_name is required")
		return
	}

	if !IsMediaFile(req.FileName) {
		writeError(w, http.StatusBadRequest, "UNSUPPORTED_TYPE", "File extension not supported")
		return
	}

	item, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Media not found")
		return
	}

	oldPath := item.FilePath
	newPath := filepath.Join(filepath.Dir(oldPath), req.FileName)

	if oldPath != newPath {
		if _, err := os.Stat(newPath); err == nil {
			writeError(w, http.StatusConflict, "FILE_EXISTS", "A file with that name already exists")
			return
		}

		if err := os.Rename(oldPath, newPath); err != nil {
			writeError(w, http.StatusInternalServerError, "RENAME_ERROR", "Failed to rename file")
			return
		}
	}

	if err := h.store.UpdateFileName(id, newPath, req.FileName, filepath.Dir(newPath)); err != nil {
		os.Rename(newPath, oldPath) // revert
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to update database")
		return
	}

	updated, err := h.store.GetByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Failed to retrieve updated item")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": updated,
	})
}

// --- helpers ---

func parseListParams(r *http.Request) ListParams {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))

	return ListParams{
		Type:    r.URL.Query().Get("type"),
		Dir:     r.URL.Query().Get("dir"),
		Sort:    r.URL.Query().Get("sort"),
		Order:   r.URL.Query().Get("order"),
		Page:    page,
		PerPage: perPage,
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
