package media

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type MediaMeta struct {
	FilePath    string
	FileName    string
	MediaType   string
	MimeType    string
	FileSize    int64
	DurationSec *float64
	Width       *int
	Height      *int
	ParentDir   string
	Checksum    string
}

type extInfo struct {
	mediaType string
	mimeType  string
}

var mediaExtensions = map[string]extInfo{
	// Video
	".mp4":  {"video", "video/mp4"},
	".mkv":  {"video", "video/x-matroska"},
	".avi":  {"video", "video/x-msvideo"},
	".mov":  {"video", "video/quicktime"},
	".wmv":  {"video", "video/x-ms-wmv"},
	".flv":  {"video", "video/x-flv"},
	".webm": {"video", "video/webm"},
	".m4v":  {"video", "video/x-m4v"},
	".ts":   {"video", "video/mp2t"},
	".mpg":  {"video", "video/mpeg"},
	".mpeg": {"video", "video/mpeg"},
	".3gp":  {"video", "video/3gpp"},

	// Audio
	".mp3":  {"audio", "audio/mpeg"},
	".flac": {"audio", "audio/flac"},
	".aac":  {"audio", "audio/aac"},
	".ogg":  {"audio", "audio/ogg"},
	".wav":  {"audio", "audio/wav"},
	".wma":  {"audio", "audio/x-ms-wma"},
	".m4a":  {"audio", "audio/mp4"},
	".opus": {"audio", "audio/opus"},
	".aiff": {"audio", "audio/aiff"},
	".alac": {"audio", "audio/mp4"},

	// Photo
	".jpg":  {"photo", "image/jpeg"},
	".jpeg": {"photo", "image/jpeg"},
	".png":  {"photo", "image/png"},
	".gif":  {"photo", "image/gif"},
	".webp": {"photo", "image/webp"},
	".bmp":  {"photo", "image/bmp"},
	".heic": {"photo", "image/heic"},
	".tiff": {"photo", "image/tiff"},
	".tif":  {"photo", "image/tiff"},
	".svg":  {"photo", "image/svg+xml"},
	".avif": {"photo", "image/avif"},
}

func IsMediaFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := mediaExtensions[ext]
	return ok
}

func ExtractMetadata(path string) (*MediaMeta, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(path))
	ei, ok := mediaExtensions[ext]
	if !ok {
		return nil, fmt.Errorf("unsupported extension: %s", ext)
	}

	meta := &MediaMeta{
		FilePath:  path,
		FileName:  info.Name(),
		MediaType: ei.mediaType,
		MimeType:  ei.mimeType,
		FileSize:  info.Size(),
		ParentDir: filepath.Dir(path),
	}

	meta.Checksum, _ = partialChecksum(path)

	if ei.mediaType == "photo" {
		w, h := imageSize(path)
		if w > 0 && h > 0 {
			meta.Width = &w
			meta.Height = &h
		}
	}

	return meta, nil
}

func partialChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	// Read first 64KB only
	_, err = io.CopyN(h, f, 64*1024)
	if err != nil && err != io.EOF {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func imageSize(path string) (int, int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}
