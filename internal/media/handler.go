package media

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
)

type Handler struct {
	store   *Store
	scanner *Scanner
}

func NewHandler(store *Store, scanner *Scanner) *Handler {
	return &Handler{store: store, scanner: scanner}
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
