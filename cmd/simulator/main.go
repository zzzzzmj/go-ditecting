package main

import (
	"context"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/bus"
	"github.com/NEU-DitingLab/go-ditecting/internal/config"
	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	eventBus, err := bus.NewNATS(cfg.NATSURL, cfg.NATSSubject, "")
	if err != nil {
		logger.Error("connect nats failed", "error", err)
		os.Exit(1)
	}
	defer eventBus.Close()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	logger.Info("industrial event simulator started", "interval", "2s")
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			event := nextEvent(now)
			if err := eventBus.Publish(ctx, event); err != nil {
				logger.Error("publish event failed", "error", err)
			} else {
				logger.Info("event published", "type", event.EventType, "protocol", event.Protocol, "asset", event.AssetIP)
			}
		}
	}
}

func nextEvent(now time.Time) domain.Event {
	base := domain.Event{ID: randomID(), AssetIP: "10.20.1.11", AssetName: "PLC-1 灌装控制器", AssetType: "PLC", Zone: "生产一区", SourceIP: "10.20.1.21", Protocol: "modbus", EventType: "telemetry", Action: "read_holding_register", Authorized: true, Success: true, OccurredAt: now, ReceivedAt: now}
	roll := rand.Intn(20)
	switch {
	case roll == 0:
		base.SourceIP = "172.16.8.66"
		base.EventType = "control"
		base.Action = "write_register"
		base.FunctionCode = 16
		base.RegisterAddress = 40001
		base.Authorized = false
	case roll == 1:
		value, min, max := 128.0, 10.0, 100.0
		base.Value = &value
		base.ExpectedMin = &min
		base.ExpectedMax = &max
	default:
		value, min, max := 58.0+rand.Float64()*4, 10.0, 100.0
		base.Value = &value
		base.ExpectedMin = &min
		base.ExpectedMax = &max
	}
	return base
}
func randomID() string { return time.Now().Format("20060102150405.000000000") }
