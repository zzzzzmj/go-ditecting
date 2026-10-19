package store

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

type Memory struct {
	mu             sync.RWMutex
	assets         map[string]domain.Asset
	events         []domain.Event
	alerts         map[int64]domain.Alert
	incidents      map[int64]domain.Incident
	nextAssetID    int64
	nextAlertID    int64
	nextIncidentID int64
}

func NewMemory() *Memory {
	return &Memory{assets: make(map[string]domain.Asset), alerts: make(map[int64]domain.Alert), incidents: make(map[int64]domain.Incident), nextAssetID: 1, nextAlertID: 1, nextIncidentID: 1}
}

func (*Memory) Close() error { return nil }

func (m *Memory) SaveEvent(_ context.Context, e domain.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	if len(m.events) > 2000 {
		m.events = append([]domain.Event(nil), m.events[len(m.events)-2000:]...)
	}
	return nil
}

func (m *Memory) UpsertAsset(_ context.Context, e domain.Event) error {
	if e.AssetIP == "" {
		return errors.New("asset_ip is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	asset, found := m.assets[e.AssetIP]
	if !found {
		asset = domain.Asset{ID: m.nextAssetID, IP: e.AssetIP, Criticality: "high"}
		m.nextAssetID++
	}
	if e.AssetName != "" {
		asset.Name = e.AssetName
	}
	if asset.Name == "" {
		asset.Name = e.AssetIP
	}
	if e.AssetType != "" {
		asset.Type = e.AssetType
	}
	if asset.Type == "" {
		asset.Type = "Unknown"
	}
	if e.Zone != "" {
		asset.Zone = e.Zone
	}
	asset.LastSeenAt = eventTime(e)
	asset.Status = "online"
	m.assets[e.AssetIP] = asset
	return nil
}

func (m *Memory) UpsertAlert(_ context.Context, e domain.Event, f domain.Finding, window time.Duration) (domain.Alert, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := eventTime(e)
	for id, alert := range m.alerts {
		if alert.Fingerprint == f.Fingerprint && alert.Status != "resolved" && now.Sub(alert.LastSeenAt) <= window {
			alert.Count++
			alert.LastSeenAt = now
			alert.Description = f.Reason
			m.alerts[id] = alert
			return alert, false, nil
		}
	}
	alert := domain.Alert{ID: m.nextAlertID, Fingerprint: f.Fingerprint, RuleID: f.RuleID, Title: f.RuleName, Description: f.Reason, Severity: f.Severity, Status: "open", TechniqueID: f.TechniqueID, AssetIP: e.AssetIP, AssetName: e.AssetName, SourceIP: e.SourceIP, Protocol: e.Protocol, Count: 1, FirstSeenAt: now, LastSeenAt: now}
	m.nextAlertID++
	m.alerts[alert.ID] = alert
	return alert, true, nil
}

func (m *Memory) ListEvents(_ context.Context, limit int) ([]domain.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	start := len(m.events) - limit
	if start < 0 {
		start = 0
	}
	items := append([]domain.Event(nil), m.events[start:]...)
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	return items, nil
}

func (m *Memory) ListAlerts(_ context.Context, status string, limit int) ([]domain.Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]domain.Alert, 0, len(m.alerts))
	for _, alert := range m.alerts {
		if status == "" || status == "all" || alert.Status == status {
			items = append(items, alert)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeenAt.After(items[j].LastSeenAt) })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (m *Memory) UpdateAlert(_ context.Context, id int64, status, assignee string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	alert, found := m.alerts[id]
	if !found {
		return errors.New("alert not found")
	}
	if status != "" {
		alert.Status = status
	}
	if assignee != "" {
		alert.Assignee = assignee
	}
	m.alerts[id] = alert
	return nil
}

func (m *Memory) ListAssets(context.Context) ([]domain.Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]domain.Asset, 0, len(m.assets))
	for _, asset := range m.assets {
		items = append(items, asset)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].IP < items[j].IP })
	return items, nil
}

func (m *Memory) Overview(_ context.Context) (domain.Overview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o := domain.Overview{AssetCount: int64(len(m.assets)), AlertsBySeverity: map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}, ProtocolCounts: make(map[string]int64)}
	for _, asset := range m.assets {
		if asset.Status == "online" {
			o.OnlineAssetCount++
		}
	}
	for _, alert := range m.alerts {
		if alert.Status != "resolved" {
			o.OpenAlertCount++
			o.AlertsBySeverity[string(alert.Severity)]++
		}
		if alert.Severity == domain.SeverityCritical && alert.Status != "resolved" {
			o.CriticalCount++
		}
	}
	o.IncidentCount = int64(len(m.incidents))
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, event := range m.events {
		if eventTime(event).After(cutoff) {
			o.EventCount24h++
		}
		protocol := strings.ToUpper(event.Protocol)
		if protocol != "" {
			o.ProtocolCounts[protocol]++
		}
	}
	return o, nil
}

func (m *Memory) CreateIncident(_ context.Context, incident domain.Incident) (domain.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	incident.ID = m.nextIncidentID
	m.nextIncidentID++
	if incident.Status == "" {
		incident.Status = "investigating"
	}
	incident.CreatedAt = time.Now()
	incident.UpdatedAt = incident.CreatedAt
	m.incidents[incident.ID] = incident
	for _, id := range incident.AlertIDs {
		if alert, ok := m.alerts[id]; ok {
			alert.Status = "investigating"
			alert.Assignee = incident.Assignee
			m.alerts[id] = alert
		}
	}
	return incident, nil
}

func (m *Memory) ListIncidents(context.Context) ([]domain.Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]domain.Incident, 0, len(m.incidents))
	for _, incident := range m.incidents {
		items = append(items, incident)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items, nil
}

func eventTime(e domain.Event) time.Time {
	if !e.OccurredAt.IsZero() {
		return e.OccurredAt
	}
	if !e.ReceivedAt.IsZero() {
		return e.ReceivedAt
	}
	return time.Now()
}
