package platform

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/bus"
	"github.com/NEU-DitingLab/go-ditecting/internal/detection"
	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
	"github.com/NEU-DitingLab/go-ditecting/internal/store"
)

type Metrics struct {
	EventsReceived   atomic.Uint64
	EventsProcessed  atomic.Uint64
	AlertsCreated    atomic.Uint64
	AlertsAggregated atomic.Uint64
}

func (m *Metrics) Prometheus() string {
	return fmt.Sprintf("# HELP ditecting_events_received_total Events accepted by the ingestion API.\n# TYPE ditecting_events_received_total counter\nditecting_events_received_total %d\n# HELP ditecting_events_processed_total Events processed by the detection engine.\n# TYPE ditecting_events_processed_total counter\nditecting_events_processed_total %d\n# HELP ditecting_alerts_created_total New alerts created.\n# TYPE ditecting_alerts_created_total counter\nditecting_alerts_created_total %d\n# HELP ditecting_alerts_aggregated_total Events aggregated into existing alerts.\n# TYPE ditecting_alerts_aggregated_total counter\nditecting_alerts_aggregated_total %d\n", m.EventsReceived.Load(), m.EventsProcessed.Load(), m.AlertsCreated.Load(), m.AlertsAggregated.Load())
}

type Service struct {
	Store       store.Store
	Bus         bus.Bus
	Engine      *detection.Engine
	AlertWindow time.Duration
	Metrics     Metrics
}

func (s *Service) Ingest(ctx context.Context, event domain.Event) (domain.Event, error) {
	if event.AssetIP == "" || event.SourceIP == "" || event.Protocol == "" || event.EventType == "" {
		return event, errors.New("asset_ip, source_ip, protocol and event_type are required")
	}
	if event.ID == "" {
		event.ID = newID()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}
	event.ReceivedAt = time.Now()
	if err := s.Bus.Publish(ctx, event); err != nil {
		return event, err
	}
	s.Metrics.EventsReceived.Add(1)
	return event, nil
}

func (s *Service) Process(ctx context.Context, event domain.Event) error {
	if err := s.Store.UpsertAsset(ctx, event); err != nil {
		return err
	}
	if err := s.Store.SaveEvent(ctx, event); err != nil {
		return err
	}
	for _, finding := range s.Engine.Evaluate(event) {
		_, created, err := s.Store.UpsertAlert(ctx, event, finding, s.AlertWindow)
		if err != nil {
			return err
		}
		if created {
			s.Metrics.AlertsCreated.Add(1)
		} else {
			s.Metrics.AlertsAggregated.Add(1)
		}
	}
	s.Metrics.EventsProcessed.Add(1)
	return nil
}

func newID() string {
	var data [12]byte
	if _, err := rand.Read(data[:]); err != nil {
		return time.Now().Format("20060102150405.000000")
	}
	return hex.EncodeToString(data[:])
}
