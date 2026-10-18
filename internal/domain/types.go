package domain

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Event struct {
	ID              string    `json:"id"`
	AssetIP         string    `json:"asset_ip"`
	AssetName       string    `json:"asset_name,omitempty"`
	AssetType       string    `json:"asset_type,omitempty"`
	Zone            string    `json:"zone,omitempty"`
	SourceIP        string    `json:"source_ip"`
	Protocol        string    `json:"protocol"`
	EventType       string    `json:"event_type"`
	Action          string    `json:"action,omitempty"`
	FunctionCode    int       `json:"function_code,omitempty"`
	RegisterAddress int       `json:"register_address,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	Value           *float64  `json:"value,omitempty"`
	ExpectedMin     *float64  `json:"expected_min,omitempty"`
	ExpectedMax     *float64  `json:"expected_max,omitempty"`
	Authorized      bool      `json:"authorized"`
	Success         bool      `json:"success"`
	OccurredAt      time.Time `json:"occurred_at"`
	ReceivedAt      time.Time `json:"received_at"`
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Severity    Severity `json:"severity"`
	TechniqueID string   `json:"technique_id"`
	Reason      string   `json:"reason"`
	Fingerprint string   `json:"fingerprint"`
}

type Alert struct {
	ID          int64     `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
	Status      string    `json:"status"`
	TechniqueID string    `json:"technique_id"`
	AssetIP     string    `json:"asset_ip"`
	AssetName   string    `json:"asset_name"`
	SourceIP    string    `json:"source_ip"`
	Protocol    string    `json:"protocol"`
	Count       int       `json:"count"`
	Assignee    string    `json:"assignee,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type Asset struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	IP          string    `json:"ip"`
	Type        string    `json:"type"`
	Zone        string    `json:"zone"`
	Vendor      string    `json:"vendor,omitempty"`
	Criticality string    `json:"criticality"`
	Status      string    `json:"status"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type Incident struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	Severity  Severity  `json:"severity"`
	Status    string    `json:"status"`
	Assignee  string    `json:"assignee"`
	AlertIDs  []int64   `json:"alert_ids"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Overview struct {
	AssetCount       int64            `json:"asset_count"`
	OnlineAssetCount int64            `json:"online_asset_count"`
	OpenAlertCount   int64            `json:"open_alert_count"`
	CriticalCount    int64            `json:"critical_count"`
	IncidentCount    int64            `json:"incident_count"`
	EventCount24h    int64            `json:"event_count_24h"`
	AlertsBySeverity map[string]int64 `json:"alerts_by_severity"`
	ProtocolCounts   map[string]int64 `json:"protocol_counts"`
}

type RuleInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	TechniqueID string   `json:"technique_id"`
	Enabled     bool     `json:"enabled"`
}
