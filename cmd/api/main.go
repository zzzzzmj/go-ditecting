package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/auth"
	"github.com/NEU-DitingLab/go-ditecting/internal/bus"
	"github.com/NEU-DitingLab/go-ditecting/internal/config"
	"github.com/NEU-DitingLab/go-ditecting/internal/detection"
	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
	"github.com/NEU-DitingLab/go-ditecting/internal/httpapi"
	"github.com/NEU-DitingLab/go-ditecting/internal/platform"
	"github.com/NEU-DitingLab/go-ditecting/internal/store"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	storage := mustStore(ctx, cfg, logger)
	defer storage.Close()
	if err := storage.Migrate(ctx); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
	if err := storage.Seed(ctx); err != nil {
		logger.Error("seed assets failed", "error", err)
		os.Exit(1)
	}

	eventBus := mustBus(cfg, cfg.Mode == "standalone", logger)
	defer eventBus.Close()
	service := &platform.Service{Store: storage, Bus: eventBus, Engine: detection.DefaultEngine(), AlertWindow: cfg.AlertWindow}
	if cfg.Mode == "standalone" {
		if err := eventBus.Subscribe(ctx, func(ctx context.Context, event domain.Event) error {
			if err := service.Process(ctx, event); err != nil {
				logger.Error("process event failed", "event_id", event.ID, "error", err)
				return err
			}
			return nil
		}); err != nil {
			logger.Error("subscribe local bus failed", "error", err)
			os.Exit(1)
		}
	}

	manager := auth.New(cfg.JWTSecret, cfg.DemoUsername, cfg.DemoPassword)
	server := httpapi.New(cfg.HTTPAddr, service, manager, cfg.IngestAPIKey, cfg.AllowedOrigins)
	logger.Info("Diting-ICS API started", "address", cfg.HTTPAddr, "mode", cfg.Mode, "storage", storageName(cfg))
	server.Spin()
}

func mustStore(ctx context.Context, cfg config.Config, logger *slog.Logger) store.Store {
	if cfg.DatabaseDSN == "" {
		logger.Info("using in-memory storage")
		return store.NewMemory()
	}
	deadline, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	db, err := store.OpenMySQL(deadline, cfg.DatabaseDSN)
	if err != nil {
		logger.Error("connect mysql failed", "error", err)
		os.Exit(1)
	}
	return db
}

func mustBus(cfg config.Config, memory bool, logger *slog.Logger) bus.Bus {
	if memory {
		logger.Info("using in-memory event bus")
		return bus.NewMemory()
	}
	n, err := bus.NewNATS(cfg.NATSURL, cfg.NATSSubject, "")
	if err != nil {
		logger.Error("connect nats failed", "error", err)
		os.Exit(1)
	}
	return n
}

func storageName(cfg config.Config) string {
	if cfg.DatabaseDSN == "" {
		return "memory"
	}
	return "mysql"
}
