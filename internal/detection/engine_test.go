package detection

import (
	"testing"
	"time"

	"github.com/NEU-DitingLab/go-ditecting/internal/domain"
)

func TestUnauthorizedModbusWrite(t *testing.T) {
	e := domain.Event{AssetIP: "10.10.2.11", SourceIP: "172.16.1.88", Protocol: "modbus", FunctionCode: 16, RegisterAddress: 40001, OccurredAt: time.Date(2026, 10, 18, 10, 0, 0, 0, time.Local)}
	findings := NewEngine(UnauthorizedWriteRule{}).Evaluate(e)
	if len(findings) != 1 || findings[0].Severity != domain.SeverityCritical {
		t.Fatalf("expected one critical finding, got %#v", findings)
	}
}

func TestAuthorizedWriteIsIgnored(t *testing.T) {
	e := domain.Event{AssetIP: "10.10.2.11", SourceIP: "10.10.1.8", Protocol: "modbus", FunctionCode: 6, Authorized: true}
	if got := NewEngine(UnauthorizedWriteRule{}).Evaluate(e); len(got) != 0 {
		t.Fatalf("expected no finding, got %#v", got)
	}
}

func TestBruteForceThreshold(t *testing.T) {
	rule := NewBruteForceRule(3, time.Minute)
	engine := NewEngine(rule)
	base := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		if got := engine.Evaluate(domain.Event{SourceIP: "1.2.3.4", AssetIP: "10.0.0.5", EventType: "authentication", OccurredAt: base.Add(time.Duration(i) * time.Second)}); len(got) != 0 {
			t.Fatalf("unexpected early finding: %#v", got)
		}
	}
	got := engine.Evaluate(domain.Event{SourceIP: "1.2.3.4", AssetIP: "10.0.0.5", EventType: "authentication", OccurredAt: base.Add(2 * time.Second)})
	if len(got) != 1 {
		t.Fatalf("expected threshold finding, got %#v", got)
	}
}

func TestProcessDeviation(t *testing.T) {
	value, min, max := 126.0, 10.0, 100.0
	e := domain.Event{AssetIP: "10.0.0.8", EventType: "telemetry", Value: &value, ExpectedMin: &min, ExpectedMax: &max}
	if got := NewEngine(ProcessDeviationRule{}).Evaluate(e); len(got) != 1 {
		t.Fatalf("expected process deviation, got %#v", got)
	}
}

func TestPortScanFiresOncePerWindow(t *testing.T) {
	rule := NewPortScanRule(3, time.Minute)
	base := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	findings := 0
	for i, port := range []int{80, 102, 502, 44818} {
		matched, _ := rule.Match(domain.Event{SourceIP: "172.16.1.9", AssetIP: "10.20.1.11", EventType: "connection", DestinationPort: port, OccurredAt: base.Add(time.Duration(i) * time.Second)})
		if matched {
			findings++
		}
	}
	if findings != 1 {
		t.Fatalf("expected one finding while above threshold, got %d", findings)
	}
}
