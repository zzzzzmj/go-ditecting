//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

func TestMySQLMigratedSchema(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	storage, err := OpenMySQL(ctx, dsn)
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	defer storage.Close()

	now := time.Now().UTC().Truncate(time.Microsecond)
	event := domain.Event{
		ID: "ci-event-001", AssetIP: "10.10.1.20", AssetName: "CI PLC", AssetType: "PLC",
		Zone: "test-zone", SourceIP: "10.10.9.9", Protocol: "modbus", EventType: "control",
		OccurredAt: now, ReceivedAt: now,
	}
	if err := storage.UpsertAsset(ctx, event); err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	if err := storage.SaveEvent(ctx, event); err != nil {
		t.Fatalf("save event: %v", err)
	}
	finding := domain.Finding{
		RuleID: "CI-RULE", RuleName: "CI detection", Severity: domain.SeverityHigh,
		Fingerprint: "ci-fingerprint", Reason: "migration integration test",
	}
	alert, created, err := storage.UpsertAlert(ctx, event, finding, 15*time.Minute)
	if err != nil {
		t.Fatalf("upsert alert: %v", err)
	}
	if !created {
		t.Fatal("expected a newly created alert")
	}
	if _, err := storage.CreateIncident(ctx, domain.Incident{
		Title: "CI incident", Summary: "schema verification", Severity: domain.SeverityHigh,
		AlertIDs: []int64{alert.ID},
	}); err != nil {
		t.Fatalf("create incident: %v", err)
	}
	overview, err := storage.Overview(ctx)
	if err != nil {
		t.Fatalf("read overview: %v", err)
	}
	if overview.AssetCount == 0 || overview.IncidentCount == 0 {
		t.Fatalf("unexpected overview: %+v", overview)
	}

	var inboxTable, rulesTable int
	if err := storage.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='event_inbox'`).Scan(&inboxTable); err != nil {
		t.Fatalf("check event_inbox: %v", err)
	}
	if err := storage.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='detection_rules'`).Scan(&rulesTable); err != nil {
		t.Fatalf("check detection_rules: %v", err)
	}
	if inboxTable != 1 || rulesTable != 1 {
		t.Fatalf("migration tables missing: event_inbox=%d detection_rules=%d", inboxTable, rulesTable)
	}
}
