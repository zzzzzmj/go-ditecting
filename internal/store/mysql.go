package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

type MySQL struct{ db *sql.DB }

func OpenMySQL(ctx context.Context, dsn string) (*MySQL, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	var last error
	for attempt := 0; attempt < 20; attempt++ {
		if last = db.PingContext(ctx); last == nil {
			return &MySQL{db: db}, nil
		}
		select {
		case <-ctx.Done():
			_ = db.Close()
			return nil, ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
	}
	_ = db.Close()
	return nil, fmt.Errorf("mysql is not ready: %w", last)
}

func (m *MySQL) Close() error { return m.db.Close() }

func (m *MySQL) Migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS assets (
			id BIGINT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(128) NOT NULL, ip VARCHAR(64) NOT NULL UNIQUE,
			type VARCHAR(64) NOT NULL DEFAULT 'Unknown', zone VARCHAR(128) NOT NULL DEFAULT '', vendor VARCHAR(128) NOT NULL DEFAULT '',
			criticality VARCHAR(16) NOT NULL DEFAULT 'high', status VARCHAR(16) NOT NULL DEFAULT 'online',
			last_seen_at DATETIME(6) NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
			updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), INDEX idx_assets_zone(zone)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS security_events (
			id BIGINT PRIMARY KEY AUTO_INCREMENT, event_id VARCHAR(64) NOT NULL UNIQUE, asset_ip VARCHAR(64) NOT NULL,
			asset_name VARCHAR(128) NOT NULL DEFAULT '', source_ip VARCHAR(64) NOT NULL, protocol VARCHAR(32) NOT NULL,
			event_type VARCHAR(64) NOT NULL, occurred_at DATETIME(6) NOT NULL, received_at DATETIME(6) NOT NULL,
			payload JSON NOT NULL, INDEX idx_events_occurred(occurred_at), INDEX idx_events_asset(asset_ip)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id BIGINT PRIMARY KEY AUTO_INCREMENT, fingerprint VARCHAR(64) NOT NULL, rule_id VARCHAR(64) NOT NULL,
			title VARCHAR(255) NOT NULL, description TEXT NOT NULL, severity VARCHAR(16) NOT NULL, status VARCHAR(24) NOT NULL DEFAULT 'open',
			technique_id VARCHAR(32) NOT NULL DEFAULT '', asset_ip VARCHAR(64) NOT NULL, asset_name VARCHAR(128) NOT NULL DEFAULT '',
			source_ip VARCHAR(64) NOT NULL, protocol VARCHAR(32) NOT NULL, occurrence_count INT NOT NULL DEFAULT 1,
			assignee VARCHAR(128) NOT NULL DEFAULT '', first_seen_at DATETIME(6) NOT NULL, last_seen_at DATETIME(6) NOT NULL,
			INDEX idx_alert_fingerprint(fingerprint, status, last_seen_at), INDEX idx_alert_status(status, severity)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS incidents (
			id BIGINT PRIMARY KEY AUTO_INCREMENT, title VARCHAR(255) NOT NULL, summary TEXT NOT NULL,
			severity VARCHAR(16) NOT NULL, status VARCHAR(24) NOT NULL DEFAULT 'investigating', assignee VARCHAR(128) NOT NULL DEFAULT '',
			alert_ids JSON NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
			INDEX idx_incident_status(status)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}
	for _, statement := range statements {
		if _, err := m.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("run migration: %w", err)
		}
	}
	return nil
}

func (m *MySQL) Seed(ctx context.Context) error {
	now := time.Now().Add(-2 * time.Minute)
	assets := []domain.Event{
		{AssetIP: "10.20.1.11", AssetName: "PLC-1 灌装控制器", AssetType: "PLC", Zone: "生产一区", OccurredAt: now},
		{AssetIP: "10.20.1.21", AssetName: "HMI-1 操作员站", AssetType: "HMI", Zone: "生产一区", OccurredAt: now},
		{AssetIP: "10.20.2.15", AssetName: "ENG-WS 工程师站", AssetType: "Workstation", Zone: "工程管理区", OccurredAt: now},
		{AssetIP: "10.20.3.10", AssetName: "SCADA-SRV 监控服务器", AssetType: "SCADA", Zone: "控制中心", OccurredAt: now},
	}
	for _, asset := range assets {
		if err := m.UpsertAsset(ctx, asset); err != nil {
			return err
		}
	}
	return nil
}

func (m *MySQL) SaveEvent(ctx context.Context, e domain.Event) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = m.db.ExecContext(ctx, `INSERT IGNORE INTO security_events(event_id,asset_ip,asset_name,source_ip,protocol,event_type,occurred_at,received_at,payload) VALUES(?,?,?,?,?,?,?,?,?)`, e.ID, e.AssetIP, e.AssetName, e.SourceIP, e.Protocol, e.EventType, eventTime(e), e.ReceivedAt, payload)
	return err
}

func (m *MySQL) UpsertAsset(ctx context.Context, e domain.Event) error {
	name := e.AssetName
	if name == "" {
		name = e.AssetIP
	}
	typeName := e.AssetType
	if typeName == "" {
		typeName = "Unknown"
	}
	_, err := m.db.ExecContext(ctx, `INSERT INTO assets(name,ip,type,zone,criticality,status,last_seen_at) VALUES(?,?,?,?,?,?,?)
		ON DUPLICATE KEY UPDATE name=IF(VALUES(name)='',name,VALUES(name)),type=IF(VALUES(type)='Unknown',type,VALUES(type)),zone=IF(VALUES(zone)='',zone,VALUES(zone)),status='online',last_seen_at=VALUES(last_seen_at)`, name, e.AssetIP, typeName, e.Zone, "high", "online", eventTime(e))
	return err
}

func (m *MySQL) UpsertAlert(ctx context.Context, e domain.Event, f domain.Finding, window time.Duration) (domain.Alert, bool, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Alert{}, false, err
	}
	defer tx.Rollback()
	cutoff := eventTime(e).Add(-window)
	row := tx.QueryRowContext(ctx, `SELECT id,fingerprint,rule_id,title,description,severity,status,technique_id,asset_ip,asset_name,source_ip,protocol,occurrence_count,assignee,first_seen_at,last_seen_at FROM alerts WHERE fingerprint=? AND status<>'resolved' AND last_seen_at>=? ORDER BY id DESC LIMIT 1 FOR UPDATE`, f.Fingerprint, cutoff)
	alert, scanErr := scanAlert(row)
	created := false
	if scanErr == nil {
		alert.Count++
		alert.LastSeenAt = eventTime(e)
		alert.Description = f.Reason
		_, err = tx.ExecContext(ctx, `UPDATE alerts SET occurrence_count=?,last_seen_at=?,description=? WHERE id=?`, alert.Count, alert.LastSeenAt, alert.Description, alert.ID)
	} else if scanErr == sql.ErrNoRows {
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO alerts(fingerprint,rule_id,title,description,severity,status,technique_id,asset_ip,asset_name,source_ip,protocol,occurrence_count,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,'open',?,?,?,?,?,1,?,?)`, f.Fingerprint, f.RuleID, f.RuleName, f.Reason, f.Severity, f.TechniqueID, e.AssetIP, e.AssetName, e.SourceIP, e.Protocol, eventTime(e), eventTime(e))
		if insertErr != nil {
			return domain.Alert{}, false, insertErr
		}
		id, _ := result.LastInsertId()
		created = true
		alert = domain.Alert{ID: id, Fingerprint: f.Fingerprint, RuleID: f.RuleID, Title: f.RuleName, Description: f.Reason, Severity: f.Severity, Status: "open", TechniqueID: f.TechniqueID, AssetIP: e.AssetIP, AssetName: e.AssetName, SourceIP: e.SourceIP, Protocol: e.Protocol, Count: 1, FirstSeenAt: eventTime(e), LastSeenAt: eventTime(e)}
	} else {
		return domain.Alert{}, false, scanErr
	}
	if err != nil {
		return domain.Alert{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Alert{}, false, err
	}
	return alert, created, nil
}

type rowScanner interface{ Scan(...any) error }

func scanAlert(row rowScanner) (domain.Alert, error) {
	var a domain.Alert
	err := row.Scan(&a.ID, &a.Fingerprint, &a.RuleID, &a.Title, &a.Description, &a.Severity, &a.Status, &a.TechniqueID, &a.AssetIP, &a.AssetName, &a.SourceIP, &a.Protocol, &a.Count, &a.Assignee, &a.FirstSeenAt, &a.LastSeenAt)
	return a, err
}

func (m *MySQL) ListEvents(ctx context.Context, limit int) ([]domain.Event, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := m.db.QueryContext(ctx, `SELECT payload FROM security_events ORDER BY occurred_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.Event, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event domain.Event
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, err
		}
		items = append(items, event)
	}
	return items, rows.Err()
}

func (m *MySQL) ListAlerts(ctx context.Context, status string, limit int) ([]domain.Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id,fingerprint,rule_id,title,description,severity,status,technique_id,asset_ip,asset_name,source_ip,protocol,occurrence_count,assignee,first_seen_at,last_seen_at FROM alerts`
	args := []any{}
	if status != "" && status != "all" {
		query += ` WHERE status=?`
		args = append(args, status)
	}
	query += ` ORDER BY last_seen_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.Alert, 0)
	for rows.Next() {
		item, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (m *MySQL) UpdateAlert(ctx context.Context, id int64, status, assignee string) error {
	if status == "" {
		_, err := m.db.ExecContext(ctx, `UPDATE alerts SET assignee=? WHERE id=?`, assignee, id)
		return err
	}
	_, err := m.db.ExecContext(ctx, `UPDATE alerts SET status=?,assignee=IF(?='',assignee,?) WHERE id=?`, status, assignee, assignee, id)
	return err
}

func (m *MySQL) ListAssets(ctx context.Context) ([]domain.Asset, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id,name,ip,type,zone,vendor,criticality,status,last_seen_at FROM assets ORDER BY INET_ATON(ip),ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.Asset, 0)
	for rows.Next() {
		var a domain.Asset
		if err := rows.Scan(&a.ID, &a.Name, &a.IP, &a.Type, &a.Zone, &a.Vendor, &a.Criticality, &a.Status, &a.LastSeenAt); err != nil {
			return nil, err
		}
		items = append(items, a)
	}
	return items, rows.Err()
}

func (m *MySQL) Overview(ctx context.Context) (domain.Overview, error) {
	o := domain.Overview{AlertsBySeverity: map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}, ProtocolCounts: make(map[string]int64)}
	queries := []struct {
		q    string
		dest *int64
	}{
		{`SELECT COUNT(*) FROM assets`, &o.AssetCount}, {`SELECT COUNT(*) FROM assets WHERE status='online'`, &o.OnlineAssetCount},
		{`SELECT COUNT(*) FROM alerts WHERE status<>'resolved'`, &o.OpenAlertCount}, {`SELECT COUNT(*) FROM alerts WHERE status<>'resolved' AND severity='critical'`, &o.CriticalCount},
		{`SELECT COUNT(*) FROM incidents WHERE status<>'closed'`, &o.IncidentCount}, {`SELECT COUNT(*) FROM security_events WHERE occurred_at>=DATE_SUB(NOW(),INTERVAL 24 HOUR)`, &o.EventCount24h},
	}
	for _, item := range queries {
		if err := m.db.QueryRowContext(ctx, item.q).Scan(item.dest); err != nil {
			return o, err
		}
	}
	rows, err := m.db.QueryContext(ctx, `SELECT severity,COUNT(*) FROM alerts WHERE status<>'resolved' GROUP BY severity`)
	if err != nil {
		return o, err
	}
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			rows.Close()
			return o, err
		}
		o.AlertsBySeverity[key] = count
	}
	rows.Close()
	rows, err = m.db.QueryContext(ctx, `SELECT UPPER(protocol),COUNT(*) FROM security_events WHERE occurred_at>=DATE_SUB(NOW(),INTERVAL 24 HOUR) GROUP BY protocol`)
	if err != nil {
		return o, err
	}
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			rows.Close()
			return o, err
		}
		o.ProtocolCounts[key] = count
	}
	rows.Close()
	return o, nil
}

func (m *MySQL) CreateIncident(ctx context.Context, incident domain.Incident) (domain.Incident, error) {
	if incident.Status == "" {
		incident.Status = "investigating"
	}
	incident.CreatedAt = time.Now()
	incident.UpdatedAt = incident.CreatedAt
	payload, _ := json.Marshal(incident.AlertIDs)
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return incident, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO incidents(title,summary,severity,status,assignee,alert_ids,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, incident.Title, incident.Summary, incident.Severity, incident.Status, incident.Assignee, payload, incident.CreatedAt, incident.UpdatedAt)
	if err != nil {
		return incident, err
	}
	incident.ID, _ = result.LastInsertId()
	if len(incident.AlertIDs) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(incident.AlertIDs)), ",")
		args := []any{incident.Assignee}
		for _, id := range incident.AlertIDs {
			args = append(args, id)
		}
		if _, err = tx.ExecContext(ctx, `UPDATE alerts SET status='investigating',assignee=? WHERE id IN (`+placeholders+`)`, args...); err != nil {
			return incident, err
		}
	}
	if err = tx.Commit(); err != nil {
		return incident, err
	}
	return incident, nil
}

func (m *MySQL) ListIncidents(ctx context.Context) ([]domain.Incident, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id,title,summary,severity,status,assignee,alert_ids,created_at,updated_at FROM incidents ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.Incident, 0)
	for rows.Next() {
		var item domain.Incident
		var payload []byte
		if err := rows.Scan(&item.ID, &item.Title, &item.Summary, &item.Severity, &item.Status, &item.Assignee, &payload, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(payload, &item.AlertIDs)
		items = append(items, item)
	}
	return items, rows.Err()
}
