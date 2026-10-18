package platform

import (
	"context"
	"testing"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/bus"
	"github.com/NEU-DitingLab/go-ditecting/internal/detection"
	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
	"github.com/NEU-DitingLab/go-ditecting/internal/store"
)

func TestStandaloneIngestToAlert(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemory()
	memoryBus := bus.NewMemory()
	service := &Service{Store: memoryStore, Bus: memoryBus, Engine: detection.NewEngine(detection.UnauthorizedWriteRule{}), AlertWindow: 15 * time.Minute}
	if err := memoryBus.Subscribe(ctx, service.Process); err != nil {
		t.Fatal(err)
	}

	event := domain.Event{AssetIP: "10.20.1.11", AssetName: "PLC-1", SourceIP: "172.16.8.66", Protocol: "modbus", EventType: "control", FunctionCode: 16}
	accepted, err := service.Ingest(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ID == "" || accepted.ReceivedAt.IsZero() {
		t.Fatalf("expected generated metadata, got %#v", accepted)
	}
	alerts, err := memoryStore.ListAlerts(ctx, "open", 10)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alerts=%#v err=%v", alerts, err)
	}
	if service.Metrics.EventsReceived.Load() != 1 || service.Metrics.EventsProcessed.Load() != 1 || service.Metrics.AlertsCreated.Load() != 1 {
		t.Fatal("unexpected service metrics")
	}
}

func TestRejectsIncompleteEvent(t *testing.T) {
	service := &Service{Bus: bus.NewMemory()}
	if _, err := service.Ingest(context.Background(), domain.Event{AssetIP: "10.0.0.1"}); err == nil {
		t.Fatal("expected validation error")
	}
}
