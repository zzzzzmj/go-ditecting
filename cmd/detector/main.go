package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/bus"
	"github.com/NEU-DitingLab/go-ditecting/internal/config"
	"github.com/NEU-DitingLab/go-ditecting/internal/detection"
	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
	"github.com/NEU-DitingLab/go-ditecting/internal/platform"
	"github.com/NEU-DitingLab/go-ditecting/internal/store"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if cfg.DatabaseDSN == "" {
		logger.Error("DATABASE_DSN is required in detector mode")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	deadline, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	storage, err := store.OpenMySQL(deadline, cfg.DatabaseDSN)
	cancel()
	if err != nil {
		logger.Error("connect mysql failed", "error", err)
		os.Exit(1)
	}
	defer storage.Close()
	if err = storage.Migrate(ctx); err != nil {
		logger.Error("migrate failed", "error", err)
		os.Exit(1)
	}
	eventBus, err := bus.NewNATS(cfg.NATSURL, cfg.NATSSubject, "diting-detectors")
	if err != nil {
		logger.Error("connect nats failed", "error", err)
		os.Exit(1)
	}
	defer eventBus.Close()
	service := &platform.Service{Store: storage, Bus: eventBus, Engine: detection.DefaultEngine(), AlertWindow: cfg.AlertWindow}
	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(service.Metrics.Prometheus()))
	})
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	metricsServer := &http.Server{Addr: cfg.MetricsAddr, Handler: metricsMux, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server failed", "error", err)
			stop()
		}
	}()
	err = eventBus.Subscribe(ctx, func(ctx context.Context, event domain.Event) error {
		if err := service.Process(ctx, event); err != nil {
			logger.Error("event processing failed", "event_id", event.ID, "error", err)
			return err
		}
		logger.Info("event processed", "event_id", event.ID, "asset_ip", event.AssetIP)
		return nil
	})
	if err != nil {
		logger.Error("subscribe failed", "error", err)
		os.Exit(1)
	}
	logger.Info("Diting-ICS detector started", "subject", cfg.NATSSubject, "queue", "diting-detectors", "metrics", cfg.MetricsAddr)
	<-ctx.Done()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = metricsServer.Shutdown(shutdownCtx)
	logger.Info("detector stopping")
}
