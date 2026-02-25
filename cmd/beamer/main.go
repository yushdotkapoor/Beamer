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

	"github.com/yushrajkapoor/beamer/internal/auth"
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

	// Ensure JWT secret exists
	jwtSecret := cfg.Auth.JWTSecret
	if jwtSecret == "" {
		// Check if stored in DB
		var stored string
		err := db.QueryRow("SELECT value FROM server_meta WHERE key = 'jwt_secret'").Scan(&stored)
		if err == nil && stored != "" {
			jwtSecret = stored
		} else {
			jwtSecret, err = auth.GenerateJWTSecret()
			if err != nil {
				slog.Error("failed to generate JWT secret", "error", err)
				os.Exit(1)
			}
			db.Exec("INSERT OR REPLACE INTO server_meta (key, value) VALUES ('jwt_secret', ?)", jwtSecret)
			slog.Info("generated new JWT signing secret")
		}
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

	jwtMgr := auth.NewJWTManager(jwtSecret, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)
	authHandler := auth.NewHandler(db, jwtMgr, cfg.Auth)

	mediaStore := media.NewStore(db)
	mediaScanner := media.NewScanner(mediaStore, cfg.Media.Directories)
	mediaHandler := media.NewHandler(mediaStore, mediaScanner)

	handler := router.New(router.Deps{
		AuthHandler:  authHandler,
		MediaHandler: mediaHandler,
		JWTManager:   jwtMgr,
		RateLimiter:  middleware.NewRateLimiter(cfg.Security.RateLimitRPS, cfg.Security.RateLimitBurst),
		AuthLimiter:  middleware.NewRateLimiter(3, 5),
		CORSOrigins:  cfg.Security.CORSOrigins,
		IPAllowlist:  cfg.Security.IPAllowlist,
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
	if cfg.Media.ScanOnStartup && len(cfg.Media.Directories) > 0 {
		go mediaScanner.FullScan()
	}

	var mediaWatcher *media.Watcher
	if cfg.Media.WatchEnabled && len(cfg.Media.Directories) > 0 {
		var err error
		mediaWatcher, err = media.NewWatcher(mediaScanner, cfg.Media.Directories)
		if err != nil {
			slog.Error("failed to create file watcher", "error", err)
		} else {
			if err := mediaWatcher.Start(); err != nil {
				slog.Error("failed to start file watcher", "error", err)
			}
		}
	}

	// Check if admin exists
	var adminCount int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&adminCount)
	if adminCount == 0 {
		slog.Info("no admin user found — register at POST /api/v1/auth/register")
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
