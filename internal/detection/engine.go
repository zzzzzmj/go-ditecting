package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

type Rule interface {
	Info() domain.RuleInfo
	Match(domain.Event) (bool, string)
}

type Engine struct{ rules []Rule }

func NewEngine(rules ...Rule) *Engine { return &Engine{rules: rules} }

func DefaultEngine() *Engine {
	return NewEngine(
		UnauthorizedWriteRule{},
		OffHoursControlRule{StartHour: 8, EndHour: 20},
		NewBruteForceRule(5, time.Minute),
		NewPortScanRule(8, 20*time.Second),
		ProcessDeviationRule{},
	)
}

func (e *Engine) Evaluate(event domain.Event) []domain.Finding {
	findings := make([]domain.Finding, 0, 2)
	for _, rule := range e.rules {
		matched, reason := rule.Match(event)
		if !matched {
			continue
		}
		info := rule.Info()
		findings = append(findings, domain.Finding{
			RuleID: info.ID, RuleName: info.Name, Severity: info.Severity,
			TechniqueID: info.TechniqueID, Reason: reason,
			Fingerprint: fingerprint(info.ID, event.AssetIP, event.SourceIP),
		})
	}
	return findings
}

func (e *Engine) Rules() []domain.RuleInfo {
	items := make([]domain.RuleInfo, 0, len(e.rules))
	for _, rule := range e.rules {
		items = append(items, rule.Info())
	}
	return items
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}

type UnauthorizedWriteRule struct{}

func (UnauthorizedWriteRule) Info() domain.RuleInfo {
	return domain.RuleInfo{ID: "ICS-MODBUS-001", Name: "Modbus 非授权写操作", Description: "检测未经授权的线圈或寄存器写入", Severity: domain.SeverityCritical, TechniqueID: "T0855", Enabled: true}
}
func (UnauthorizedWriteRule) Match(e domain.Event) (bool, string) {
	if !isModbus(e.Protocol) || e.Authorized {
		return false, ""
	}
	if e.FunctionCode == 5 || e.FunctionCode == 6 || e.FunctionCode == 15 || e.FunctionCode == 16 {
		return true, fmt.Sprintf("源主机 %s 未经授权执行 Modbus 功能码 %d，目标寄存器 %d", e.SourceIP, e.FunctionCode, e.RegisterAddress)
	}
	return false, ""
}

type OffHoursControlRule struct{ StartHour, EndHour int }

func (OffHoursControlRule) Info() domain.RuleInfo {
	return domain.RuleInfo{ID: "ICS-TIME-002", Name: "非工作时段控制指令", Description: "检测预定维护窗口外的工业控制指令", Severity: domain.SeverityHigh, TechniqueID: "T0855", Enabled: true}
}
func (r OffHoursControlRule) Match(e domain.Event) (bool, string) {
	if !isWrite(e) || e.OccurredAt.IsZero() {
		return false, ""
	}
	hour := e.OccurredAt.Hour()
	if hour < r.StartHour || hour >= r.EndHour {
		return true, fmt.Sprintf("在 %02d:%02d 检测到控制写操作，超出 %02d:00-%02d:00 允许窗口", hour, e.OccurredAt.Minute(), r.StartHour, r.EndHour)
	}
	return false, ""
}

type ProcessDeviationRule struct{}

func (ProcessDeviationRule) Info() domain.RuleInfo {
	return domain.RuleInfo{ID: "ICS-PROCESS-005", Name: "工艺参数越界", Description: "检测超出预期运行范围的工艺值", Severity: domain.SeverityHigh, TechniqueID: "T0836", Enabled: true}
}
func (ProcessDeviationRule) Match(e domain.Event) (bool, string) {
	if e.Value == nil {
		return false, ""
	}
	if e.ExpectedMin != nil && *e.Value < *e.ExpectedMin {
		return true, fmt.Sprintf("工艺值 %.2f 低于安全下限 %.2f", *e.Value, *e.ExpectedMin)
	}
	if e.ExpectedMax != nil && *e.Value > *e.ExpectedMax {
		return true, fmt.Sprintf("工艺值 %.2f 高于安全上限 %.2f", *e.Value, *e.ExpectedMax)
	}
	return false, ""
}

type BruteForceRule struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	failures  map[string][]time.Time
}

func NewBruteForceRule(threshold int, window time.Duration) *BruteForceRule {
	return &BruteForceRule{threshold: threshold, window: window, failures: make(map[string][]time.Time)}
}
func (*BruteForceRule) Info() domain.RuleInfo {
	return domain.RuleInfo{ID: "ICS-AUTH-003", Name: "工业设备认证爆破", Description: "检测短时间内的连续认证失败", Severity: domain.SeverityHigh, TechniqueID: "T0806", Enabled: true}
}
func (r *BruteForceRule) Match(e domain.Event) (bool, string) {
	if e.EventType != "authentication" || e.Success {
		return false, ""
	}
	now := eventTime(e)
	key := e.SourceIP + "|" + e.AssetIP
	r.mu.Lock()
	defer r.mu.Unlock()
	items := append(r.failures[key], now)
	cutoff := now.Add(-r.window)
	kept := items[:0]
	for _, item := range items {
		if !item.Before(cutoff) {
			kept = append(kept, item)
		}
	}
	r.failures[key] = kept
	if len(kept) == r.threshold {
		return true, fmt.Sprintf("%s 在 %s 内对 %s 连续认证失败 %d 次", e.SourceIP, r.window, e.AssetIP, len(kept))
	}
	return false, ""
}

type PortScanRule struct {
	mu           sync.Mutex
	threshold    int
	window       time.Duration
	observations map[string]map[int]time.Time
	alerted      map[string]bool
}

func NewPortScanRule(threshold int, window time.Duration) *PortScanRule {
	return &PortScanRule{threshold: threshold, window: window, observations: make(map[string]map[int]time.Time), alerted: make(map[string]bool)}
}
func (*PortScanRule) Info() domain.RuleInfo {
	return domain.RuleInfo{ID: "ICS-DISCOVERY-004", Name: "OT 网段端口扫描", Description: "检测单一源对工业资产的多端口探测", Severity: domain.SeverityMedium, TechniqueID: "T0846", Enabled: true}
}
func (r *PortScanRule) Match(e domain.Event) (bool, string) {
	if e.EventType != "connection" || e.DestinationPort == 0 {
		return false, ""
	}
	now := eventTime(e)
	r.mu.Lock()
	defer r.mu.Unlock()
	ports := r.observations[e.SourceIP]
	if ports == nil {
		ports = make(map[int]time.Time)
		r.observations[e.SourceIP] = ports
	}
	for port, seen := range ports {
		if now.Sub(seen) > r.window {
			delete(ports, port)
		}
	}
	if len(ports) < r.threshold {
		r.alerted[e.SourceIP] = false
	}
	ports[e.DestinationPort] = now
	if len(ports) >= r.threshold && !r.alerted[e.SourceIP] {
		r.alerted[e.SourceIP] = true
		values := make([]int, 0, len(ports))
		for port := range ports {
			values = append(values, port)
		}
		sort.Ints(values)
		return true, fmt.Sprintf("源主机 %s 在 %s 内探测了 %d 个端口: %v", e.SourceIP, r.window, len(values), values)
	}
	return false, ""
}

func isModbus(protocol string) bool {
	value := strings.ToLower(protocol)
	return value == "modbus" || value == "modbus/tcp"
}
func isWrite(e domain.Event) bool {
	return isModbus(e.Protocol) && (e.FunctionCode == 5 || e.FunctionCode == 6 || e.FunctionCode == 15 || e.FunctionCode == 16)
}
func eventTime(e domain.Event) time.Time {
	if !e.OccurredAt.IsZero() {
		return e.OccurredAt
	}
	return time.Now()
}
