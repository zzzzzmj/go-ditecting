package store

import (
	"context"
	"testing"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

func TestAlertAggregation(t *testing.T) {
	s := NewMemory()
	e := domain.Event{AssetIP: "10.0.0.1", AssetName: "PLC", SourceIP: "10.0.0.9", Protocol: "modbus", OccurredAt: time.Now()}
	f := domain.Finding{RuleID: "R1", RuleName: "test", Severity: domain.SeverityHigh, Fingerprint: "same"}
	first, created, err := s.UpsertAlert(context.Background(), e, f, 15*time.Minute)
	if err != nil || !created {
		t.Fatalf("first upsert: created=%v err=%v", created, err)
	}
	second, created, err := s.UpsertAlert(context.Background(), e, f, 15*time.Minute)
	if err != nil || created || second.ID != first.ID || second.Count != 2 {
		t.Fatalf("second upsert: %#v created=%v err=%v", second, created, err)
	}
}
