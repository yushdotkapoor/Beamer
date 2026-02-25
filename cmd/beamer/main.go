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

	if err := beamertls.EnsureCert(cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.Hosts); err != nil {
		slog.Error("failed to ensure TLS certificate", "error", err)
		os.Exit(1)
	}

	tlsConfig, err := beamertls.LoadTLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		slog.Error("failed to load TLS config", "error", err)
		os.Exit(1)
	}

	mux := router.New()

	srv := &http.Server{
		Addr:         cfg.Address(),
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("beamer is running", "address", fmt.Sprintf("https://%s", cfg.Address()))
		// TLS is configured via TLSConfig, so use ServeTLS with empty cert/key paths
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	slog.Info("shutting down", "signal", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
