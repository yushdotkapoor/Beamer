package media

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxUploadWorkers = 4

type batchFileResult struct {
	FileName string    `json:"file_name"`
	Status   string    `json:"status"`
	Error    *batchErr `json:"error,omitempty"`
	Item     *MediaItem `json:"item,omitempty"`
}

type batchErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Handler struct {
	store         *Store
	scanner       *Scanner
	uploadDir     string
	thumbnailDir  string
}

func NewHandler(store *Store, scanner *Scanner, uploadDir, thumbnailDir string) *Handler {
	return &Handler{store: store, scanner: scanner, uploadDir: uploadDir, thumbnailDir: thumbnailDir}
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

	switch item.MediaType {
	case "photo":
		h.servePhotoThumbnail(w, r, item)
	case "video":
		h.serveVideoThumbnail(w, r, item)
	default:
		writeError(w, http.StatusNotFound, "NO_THUMBNAIL", "Thumbnails not available for this media type")
	}
}

func (h *Handler) servePhotoThumbnail(w http.ResponseWriter, r *http.Request, item *MediaItem) {
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

func (h *Handler) serveVideoThumbnail(w http.ResponseWriter, r *http.Request, item *MediaItem) {
	// Check for cached thumbnail
	thumbPath := filepath.Join(h.thumbnailDir, fmt.Sprintf("%d.jpg", item.ID))

	if f, err := os.Open(thumbPath); err == nil {
		defer f.Close()
		stat, err := f.Stat()
		if err == nil {
			w.Header().Set("Content-Type", "image/jpeg")
			http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
			return
		}
	}

	// Generate thumbnail via ffmpeg
	if err := h.generateVideoThumbnail(item.FilePath, thumbPath); err != nil {
		slog.Error("failed to generate video thumbnail", "id", item.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "THUMBNAIL_ERROR", "Failed to generate thumbnail")
		return
	}

	f, err := os.Open(thumbPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "THUMBNAIL_ERROR", "Failed to read generated thumbnail")
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STAT_ERROR", "Failed to read thumbnail")
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

func (h *Handler) generateVideoThumbnail(videoPath, thumbPath string) error {
	// Use ffmpeg to extract a frame at 50% of duration
	// First get duration via ffprobe
	probeCmd := exec.Command("/usr/local/bin/ffprobe",
		"-v", "error",
		"-show_entries", "format=duration",
		"-of", "default=noprint_wrappers=1:nokey=1",
		videoPath,
	)
	durationOut, err := probeCmd.Output()
	if err != nil {
		return fmt.Errorf("ffprobe failed: %w", err)
	}

	durationStr := strings.TrimSpace(string(durationOut))
	duration, err := strconv.ParseFloat(durationStr, 64)
	if err != nil {
		duration = 1.0 // fallback: grab first frame
	}

	seekTo := fmt.Sprintf("%.2f", duration/2)

	cmd := exec.Command("/usr/local/bin/ffmpeg",
		"-ss", seekTo,
		"-i", videoPath,
		"-vframes", "1",
		"-q:v", "3",
		"-y",
		thumbPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ffmpeg failed: %w: %s", err, string(out))
	}

	return nil
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

func (h *Handler) BatchUploadMedia(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "PARSE_ERROR", "Failed to parse upload")
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "NO_FILES", "No files provided in 'files' field")
		return
	}

	results := make([]batchFileResult, len(files))

	sem := make(chan struct{}, maxUploadWorkers)
	var wg sync.WaitGroup

	for i, fh := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, header *multipart.FileHeader) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = h.processOneUpload(header)
		}(i, fh)
	}

	wg.Wait()

	var succeeded, failed int
	for _, res := range results {
		if res.Status == "success" {
			succeeded++
		} else {
			failed++
		}
	}

	statusCode := http.StatusOK
	if failed > 0 {
		statusCode = 207
	}

	writeJSON(w, statusCode, map[string]interface{}{
		"data": map[string]interface{}{
			"results": results,
			"summary": map[string]int{
				"total":     len(files),
				"succeeded": succeeded,
				"failed":    failed,
			},
		},
	})
}

func (h *Handler) processOneUpload(header *multipart.FileHeader) batchFileResult {
	filename := header.Filename

	if !IsMediaFile(filename) {
		return batchFileResult{
			FileName: filename,
			Status:   "error",
			Error:    &batchErr{Code: "UNSUPPORTED_TYPE", Message: "File type not supported"},
		}
	}

	file, err := header.Open()
	if err != nil {
		return batchFileResult{
			FileName: filename,
			Status:   "error",
			Error:    &batchErr{Code: "READ_ERROR", Message: "Failed to read uploaded file"},
		}
	}
	defer file.Close()

	destPath := filepath.Join(h.uploadDir, filename)
	if _, err := os.Stat(destPath); err == nil {
		ext := filepath.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		destPath = filepath.Join(h.uploadDir, fmt.Sprintf("%s_%d%s", base, time.Now().UnixNano(), ext))
	}

	dest, err := os.Create(destPath)
	if err != nil {
		slog.Error("batch upload: failed to create file", "path", destPath, "error", err)
		return batchFileResult{
			FileName: filename,
			Status:   "error",
			Error:    &batchErr{Code: "WRITE_ERROR", Message: "Failed to save file"},
		}
	}

	if _, err := io.Copy(dest, file); err != nil {
		dest.Close()
		os.Remove(destPath)
		return batchFileResult{
			FileName: filename,
			Status:   "error",
			Error:    &batchErr{Code: "WRITE_ERROR", Message: "Failed to write file"},
		}
	}
	dest.Close()

	h.scanner.ScanFile(destPath)

	item, err := h.store.GetByFilePath(destPath)
	if err != nil {
		return batchFileResult{
			FileName: filepath.Base(destPath),
			Status:   "success",
		}
	}

	return batchFileResult{
		FileName: filepath.Base(destPath),
		Status:   "success",
		Item:     item,
	}
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

	// Remove cached thumbnail if it exists
	thumbPath := filepath.Join(h.thumbnailDir, fmt.Sprintf("%d.jpg", id))
	os.Remove(thumbPath)

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
