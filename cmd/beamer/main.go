package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yushrajkapoor/beamer/internal/config"
	"github.com/yushrajkapoor/beamer/internal/database"
	"github.com/yushrajkapoor/beamer/internal/media"
	"github.com/yushrajkapoor/beamer/internal/middleware"
	"github.com/yushrajkapoor/beamer/internal/router"
	beamertls "github.com/yushrajkapoor/beamer/internal/tls"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	setupLogger("info", "text")

	slog.Info("starting beamer", "version", Version, "build_time", BuildTime)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	setupLogger(cfg.Logging.Level, cfg.Logging.Format)

	db, err := database.Open(cfg.Database)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := database.Migrate(db); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Generate CA, server cert, and client cert for mTLS
	certPaths := beamertls.CertPaths{
		CACert:     cfg.TLS.CACertFile,
		CAKey:      cfg.TLS.CAKeyFile,
		ServerCert: cfg.TLS.CertFile,
		ServerKey:  cfg.TLS.KeyFile,
		ClientCert: cfg.TLS.ClientCert,
		ClientKey:  cfg.TLS.ClientKey,
		ClientP12:  cfg.TLS.ClientP12,
		Hosts:      cfg.TLS.Hosts,
	}
	if err := beamertls.EnsureMTLSCerts(certPaths); err != nil {
		slog.Error("failed to ensure mTLS certificates", "error", err)
		os.Exit(1)
	}

	tlsConfig, err := beamertls.LoadMTLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CACertFile)
	if err != nil {
		slog.Error("failed to load mTLS config", "error", err)
		os.Exit(1)
	}

	certFingerprint, err := beamertls.CertFingerprint(cfg.TLS.CertFile)
	if err != nil {
		slog.Error("failed to compute cert fingerprint", "error", err)
		os.Exit(1)
	}
	slog.Info("certificate fingerprint", "sha256", certFingerprint)

	// Merge upload directory into scanned directories
	allMediaDirs := cfg.Media.Directories
	if cfg.Media.UploadDirectory != "" {
		found := false
		for _, d := range allMediaDirs {
			if d == cfg.Media.UploadDirectory {
				found = true
				break
			}
		}
		if !found {
			allMediaDirs = append(allMediaDirs, cfg.Media.UploadDirectory)
		}
	}

	mediaStore := media.NewStore(db)
	mediaScanner := media.NewScanner(mediaStore, allMediaDirs)
	mediaHandler := media.NewHandler(mediaStore, mediaScanner, cfg.Media.UploadDirectory, cfg.Media.ThumbnailCache)

	handler := router.New(router.Deps{
		MediaHandler:    mediaHandler,
		RateLimiter:     middleware.NewRateLimiter(cfg.Security.RateLimitRPS, cfg.Security.RateLimitBurst),
		CORSOrigins:     cfg.Security.CORSOrigins,
		IPAllowlist:     cfg.Security.IPAllowlist,
		CertFingerprint: certFingerprint,
	})

	srv := &http.Server{
		Addr:         cfg.Address(),
		Handler:      handler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Media scanning
	if cfg.Media.ScanOnStartup && len(allMediaDirs) > 0 {
		go mediaScanner.FullScan()
	}

	var mediaWatcher *media.Watcher
	if cfg.Media.WatchEnabled && len(allMediaDirs) > 0 {
		var err error
		mediaWatcher, err = media.NewWatcher(mediaScanner, allMediaDirs)
		if err != nil {
			slog.Error("failed to create file watcher", "error", err)
		} else {
			if err := mediaWatcher.Start(); err != nil {
				slog.Error("failed to start file watcher", "error", err)
			}
		}
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("beamer is running", "address", fmt.Sprintf("https://%s", cfg.Address()))
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	slog.Info("shutting down", "signal", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if mediaWatcher != nil {
		mediaWatcher.Stop()
	}

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("beamer stopped")
}

func setupLogger(level, format string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))
}
