package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	TLS      TLSConfig      `yaml:"tls"`
	Database DatabaseConfig `yaml:"database"`
	Media    MediaConfig    `yaml:"media"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

type TLSConfig struct {
	CACertFile string   `yaml:"ca_cert_file"`
	CAKeyFile  string   `yaml:"ca_key_file"`
	CertFile   string   `yaml:"cert_file"`
	KeyFile    string   `yaml:"key_file"`
	ClientCert string   `yaml:"client_cert_file"`
	ClientKey  string   `yaml:"client_key_file"`
	ClientP12  string   `yaml:"client_p12_file"`
	Hosts      []string `yaml:"hosts"`
}

type DatabaseConfig struct {
	Path        string `yaml:"path"`
	JournalMode string `yaml:"journal_mode"`
	BusyTimeout int    `yaml:"busy_timeout"`
	CacheSize   int    `yaml:"cache_size"`
	Synchronous string `yaml:"synchronous"`
}


type MediaConfig struct {
	Directories     []string `yaml:"directories"`
	UploadDirectory string   `yaml:"upload_directory"`
	ScanOnStartup   bool     `yaml:"scan_on_startup"`
	WatchEnabled    bool     `yaml:"watch_enabled"`
	ThumbnailCache  string   `yaml:"thumbnail_cache"`
}

type SecurityConfig struct {
	CORSOrigins    []string `yaml:"cors_origins"`
	IPAllowlist    []string `yaml:"ip_allowlist"`
	RateLimitRPS   float64  `yaml:"rate_limit_rps"`
	RateLimitBurst int      `yaml:"rate_limit_burst"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8443,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 0,
			IdleTimeout:  120 * time.Second,
		},
		TLS: TLSConfig{
			CACertFile: "./data/ca_cert.pem",
			CAKeyFile:  "./data/ca_key.pem",
			CertFile:   "./data/cert.pem",
			KeyFile:    "./data/key.pem",
			ClientCert: "./data/client_cert.pem",
			ClientKey:  "./data/client_key.pem",
			ClientP12:  "./data/client.p12",
			Hosts:      []string{"localhost"},
		},
		Database: DatabaseConfig{
			Path:        "./data/beamer.db",
			JournalMode: "WAL",
			BusyTimeout: 5000,
			CacheSize:   -2000,
			Synchronous: "NORMAL",
		},
		Media: MediaConfig{
			UploadDirectory: "./data/uploads",
			ScanOnStartup:   true,
			WatchEnabled:    true,
			ThumbnailCache:  "./data/thumbnails",
		},
		Security: SecurityConfig{
			RateLimitRPS:   100,
			RateLimitBurst: 200,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()

	configPath := path
	if configPath == "" {
		configPath = findConfigFile()
	}

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	applyEnvOverrides(cfg)

	if err := cfg.ensureDirectories(); err != nil {
		return nil, fmt.Errorf("creating directories: %w", err)
	}

	return cfg, nil
}

func (c *Config) Address() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

func (c *Config) WriteDefault(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func (c *Config) ensureDirectories() error {
	dirs := []string{
		filepath.Dir(c.Database.Path),
		filepath.Dir(c.TLS.CertFile),
		c.Media.ThumbnailCache,
		c.Media.UploadDirectory,
	}
	for _, dir := range dirs {
		if dir == "" || dir == "." {
			continue
		}
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	return nil
}

func findConfigFile() string {
	candidates := []string{
		"./beamer.yaml",
	}

	home, err := os.UserHomeDir()
	if err == nil {
		candidates = append(candidates, filepath.Join(home, ".config", "beamer", "beamer.yaml"))
	}
	candidates = append(candidates, "/etc/beamer/beamer.yaml")

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func applyEnvOverrides(cfg *Config) {
	applyEnvToStruct("BEAMER", reflect.ValueOf(cfg).Elem())
}

func applyEnvToStruct(prefix string, v reflect.Value) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldVal := v.Field(i)

		tag := field.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		envKey := prefix + "_" + strings.ToUpper(tag)

		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Duration(0)) {
			applyEnvToStruct(envKey, fieldVal)
			continue
		}

		envVal, ok := os.LookupEnv(envKey)
		if !ok {
			continue
		}

		switch fieldVal.Interface().(type) {
		case string:
			fieldVal.SetString(envVal)
		case int:
			if n, err := strconv.Atoi(envVal); err == nil {
				fieldVal.SetInt(int64(n))
			}
		case float64:
			if f, err := strconv.ParseFloat(envVal, 64); err == nil {
				fieldVal.SetFloat(f)
			}
		case bool:
			if b, err := strconv.ParseBool(envVal); err == nil {
				fieldVal.SetBool(b)
			}
		case time.Duration:
			if d, err := time.ParseDuration(envVal); err == nil {
				fieldVal.Set(reflect.ValueOf(d))
			}
		case []string:
			fieldVal.Set(reflect.ValueOf(strings.Split(envVal, ",")))
		}
	}
}
