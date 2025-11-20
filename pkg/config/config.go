package config

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server settings
	Port            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// Security secrets (required)
	JWTSecret  []byte
	XSRFSecret []byte

	// Auth/Cookie settings
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	CookieSecure         bool

	// Storage settings
	UploadPath   string
	MaxFileSize  int64

	// Rate limiting
	AuthRateLimit     float64
	RateLimitWindow   time.Duration

	// Job queue settings
	JobPollInterval time.Duration
	JobBatchSize    int
	JobMaxRetries   int
	JobTimeout      time.Duration

	// AI/Processing timeouts
	ContentFetchTimeout time.Duration
	AIProcessingTimeout time.Duration

	// CORS
	CORSMaxAge int
}

// Load reads configuration from environment variables with sensible defaults
func Load() (*Config, error) {
	cfg := &Config{}

	// Server settings
	cfg.Port = getEnv("PORT", "8081")
	cfg.ReadTimeout = getDuration("READ_TIMEOUT", 15*time.Second)
	cfg.WriteTimeout = getDuration("WRITE_TIMEOUT", 15*time.Second)
	cfg.IdleTimeout = getDuration("IDLE_TIMEOUT", 60*time.Second)
	cfg.ShutdownTimeout = getDuration("SHUTDOWN_TIMEOUT", 30*time.Second)

	// Security secrets (required)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is required")
	}
	cfg.JWTSecret = []byte(jwtSecret)

	xsrfSecret := os.Getenv("XSRF_SECRET")
	if xsrfSecret == "" {
		return nil, fmt.Errorf("XSRF_SECRET environment variable is required")
	}
	cfg.XSRFSecret = []byte(xsrfSecret)

	// Auth/Cookie settings
	cfg.AccessTokenDuration = getDuration("ACCESS_TOKEN_DURATION", 15*time.Minute)
	cfg.RefreshTokenDuration = getDuration("REFRESH_TOKEN_DURATION", 7*24*time.Hour)
	cfg.CookieSecure = getBool("COOKIE_SECURE", true)

	// Storage settings
	defaultUploadPath := ""
	if home, err := os.UserHomeDir(); err == nil {
		defaultUploadPath = path.Join(home, "org", "uploads")
	}
	cfg.UploadPath = os.ExpandEnv(getEnv("UPLOAD_PATH", defaultUploadPath))
	cfg.MaxFileSize = getInt64("MAX_FILE_SIZE", 10*1024*1024) // 10MB

	// Rate limiting
	cfg.AuthRateLimit = getFloat64("AUTH_RATE_LIMIT", 5)
	cfg.RateLimitWindow = getDuration("RATE_LIMIT_WINDOW", time.Minute)

	// Job queue settings
	cfg.JobPollInterval = getDuration("JOB_POLL_INTERVAL", 10*time.Second)
	cfg.JobBatchSize = getInt("JOB_BATCH_SIZE", 5)
	cfg.JobMaxRetries = getInt("JOB_MAX_RETRIES", 3)
	cfg.JobTimeout = getDuration("JOB_TIMEOUT", 5*time.Minute)

	// AI/Processing timeouts
	cfg.ContentFetchTimeout = getDuration("CONTENT_FETCH_TIMEOUT", 30*time.Second)
	cfg.AIProcessingTimeout = getDuration("AI_PROCESSING_TIMEOUT", 180*time.Second)

	// CORS
	cfg.CORSMaxAge = getInt("CORS_MAX_AGE", 3600)

	return cfg, nil
}

// Helper functions for parsing environment variables

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

func getFloat64(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			return f
		}
	}
	return defaultValue
}
