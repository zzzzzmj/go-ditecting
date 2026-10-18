package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment    string
	HTTPAddr       string
	MetricsAddr    string
	Mode           string
	DatabaseDSN    string
	NATSURL        string
	NATSSubject    string
	JWTSecret      string
	DemoUsername   string
	DemoPassword   string
	IngestAPIKey   string
	AllowedOrigins string
	AlertWindow    time.Duration
}

func Load() Config {
	return Config{
		Environment:    env("APP_ENV", "development"),
		HTTPAddr:       env("HTTP_ADDR", ":8080"),
		MetricsAddr:    env("METRICS_ADDR", ":9091"),
		Mode:           env("APP_MODE", "standalone"),
		DatabaseDSN:    os.Getenv("DATABASE_DSN"),
		NATSURL:        env("NATS_URL", "nats://localhost:4222"),
		NATSSubject:    env("NATS_SUBJECT", "ics.events"),
		JWTSecret:      env("JWT_SECRET", "development-only-change-me-please"),
		DemoUsername:   env("DEMO_USERNAME", "analyst"),
		DemoPassword:   env("DEMO_PASSWORD", "diting2026"),
		IngestAPIKey:   env("INGEST_API_KEY", "diting-ingest-key"),
		AllowedOrigins: env("ALLOWED_ORIGINS", "http://localhost:8080"),
		AlertWindow:    time.Duration(envInt("ALERT_AGGREGATION_MINUTES", 15)) * time.Minute,
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return value
}
