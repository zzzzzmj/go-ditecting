package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const defaultSourceURL = "file://db/migrations"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(os.Args[1:], logger); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, logger *slog.Logger) error {
	databaseURL := os.Getenv("MIGRATION_DATABASE_URL")
	if databaseURL == "" {
		return errors.New("MIGRATION_DATABASE_URL is required")
	}
	sourceURL := os.Getenv("MIGRATION_SOURCE_URL")
	if sourceURL == "" {
		sourceURL = defaultSourceURL
	}

	m, err := migrate.New(sourceURL, databaseURL)
	if err != nil {
		return fmt.Errorf("initialize migrator: %w", err)
	}
	defer func() {
		sourceErr, databaseErr := m.Close()
		if sourceErr != nil {
			logger.Warn("close migration source", "error", sourceErr)
		}
		if databaseErr != nil {
			logger.Warn("close migration database", "error", databaseErr)
		}
	}()
	m.LockTimeout = 60 * time.Second

	command := "up"
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "up":
		err = migrateUp(m, args[1:])
	case "version":
		if len(args) != 1 {
			return errors.New("usage: migrate version")
		}
	default:
		return fmt.Errorf("unsupported command %q; use up [steps] or version", command)
	}
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	version, dirty, versionErr := m.Version()
	if errors.Is(versionErr, migrate.ErrNilVersion) {
		logger.Info("database has no applied migration")
		return nil
	}
	if versionErr != nil {
		return fmt.Errorf("read schema version: %w", versionErr)
	}
	if dirty {
		return fmt.Errorf("schema version %d is dirty", version)
	}
	logger.Info("database schema is ready", "version", version, "dirty", false)
	return nil
}

func migrateUp(m *migrate.Migrate, args []string) error {
	if len(args) == 0 {
		return m.Up()
	}
	if len(args) != 1 {
		return errors.New("usage: migrate up [steps]")
	}
	steps, err := strconv.Atoi(args[0])
	if err != nil || steps <= 0 {
		return errors.New("migration steps must be a positive integer")
	}
	return m.Steps(steps)
}
