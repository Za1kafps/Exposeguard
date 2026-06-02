package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Za1kafps/exposeguard/internal/model"
)

func TestRenderReports(t *testing.T) {
	rep := model.Report{
		Metadata: model.Metadata{Tool: "exposeguard", Version: "test", GeneratedAt: time.Unix(0, 0), Hostname: "host"},
		Findings: []model.Finding{{
			ID: "EG-CRITICAL-001", Title: "PostgreSQL is publicly exposed", Severity: model.SeverityCritical,
			RuleID: "EG-CRITICAL-001", Reason: "public binding", Impact: "reachable",
			Fixes: []model.Fix{{Title: "Bind locally", Summary: "bind to localhost", Safe: true}},
		}},
	}
	rep.Summary = model.BuildSummary(rep.Findings)

	tests := []struct {
		name   string
		format Format
		want   string
	}{
		{name: "terminal", format: FormatTerminal, want: "CRITICAL"},
		{name: "json", format: FormatJSON, want: `"findings"`},
		{name: "markdown", format: FormatMarkdown, want: "## Findings"},
		{name: "sarif", format: FormatSARIF, want: `"version": "2.1.0"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Render(tt.format, rep)
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}
			if !strings.Contains(string(data), tt.want) {
				t.Fatalf("rendered report does not contain %q:\n%s", tt.want, data)
			}
		})
	}
}

func TestRenderTerminalConciseHidesDiagnostics(t *testing.T) {
	rep := model.Report{
		Metadata: model.Metadata{Tool: "exposeguard", Version: "test", GeneratedAt: time.Unix(0, 0), Hostname: "host"},
		Findings: []model.Finding{
			{
				ID: "EG-MEDIUM-001", Title: "Unknown public Docker service", Severity: model.SeverityMedium,
				Binding: "0.0.0.0:8080", Protocol: "tcp", Reason: "full reason", Impact: "full impact",
				Evidence: []model.Evidence{{Source: "docker", Summary: "long evidence", Confidence: "high"}},
				Fixes:    []model.Fix{{Title: "Bind locally", Summary: "bind to localhost", Safe: true}, {Title: "Remove", Summary: "remove the port", Safe: true}},
			},
			{ID: "EG-INFO-002", Title: "Firewall state is unknown", Severity: model.SeverityInfo, Fixes: []model.Fix{{Title: "Read firewall", Summary: "run as root", Safe: true}}},
		},
		Warnings: []model.Warning{{Source: "firewall", Message: "iptables-save failed"}},
	}
	rep.Summary = model.BuildSummary(rep.Findings)

	got := RenderTerminal(rep, RenderOptions{DetailHint: "exposeguard scan --verbose"})
	for _, hidden := range []string{"Warnings\n", "long evidence", "full impact", "Firewall state is unknown", "iptables-save failed"} {
		if strings.Contains(got, hidden) {
			t.Fatalf("concise report leaked %q:\n%s", hidden, got)
		}
	}
	for _, want := range []string{"Scan status: incomplete", "Unknown public Docker service", "Fix: bind to localhost", "More details:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("concise report missing %q:\n%s", want, got)
		}
	}
}

func TestRenderTerminalVerboseIncludesDiagnostics(t *testing.T) {
	rep := model.Report{
		Metadata: model.Metadata{Tool: "exposeguard", Version: "test", GeneratedAt: time.Unix(0, 0)},
		Findings: []model.Finding{{
			ID: "EG-INFO-001", Title: "Firewall state is unknown", Severity: model.SeverityInfo,
			Reason: "full reason", Impact: "full impact",
			Evidence: []model.Evidence{{Source: "firewall", Summary: "full evidence", Confidence: "low"}},
			Fixes:    []model.Fix{{Title: "Fix", Summary: "full fix", Safe: true}},
		}},
		Warnings: []model.Warning{{Source: "firewall", Message: "full warning"}},
	}
	rep.Summary = model.BuildSummary(rep.Findings)

	got := RenderTerminal(rep, RenderOptions{Verbose: true})
	for _, want := range []string{"Warnings\n", "full warning", "INFO", "full reason", "full impact", "full evidence", "full fix"} {
		if !strings.Contains(got, want) {
			t.Fatalf("verbose report missing %q:\n%s", want, got)
		}
	}
}

func TestSARIFMappingAndFingerprint(t *testing.T) {
	finding := model.Finding{
		ID: "EG-HIGH-006", RuleID: "EG-HIGH-006", Title: "Backend is reachable directly, bypassing the reverse proxy", Severity: model.SeverityHigh,
		ServiceName: "api", ContainerName: "project-api-1", Binding: "0.0.0.0:3000", Protocol: "tcp",
		Compose:       &model.ComposeEvidence{File: "docker-compose.yml", ServiceName: "api"},
		PublishedPort: &model.PublishedPortEvidence{HostIP: "0.0.0.0", HostPort: 3000, ContainerPort: 3000, Protocol: "tcp"},
		Intent:        model.ServiceIntent{Category: "internal-api", Confidence: "medium"},
		Reason:        "direct backend port",
		Impact:        "proxy policy can be bypassed",
		Fixes:         []model.Fix{{Title: "Remove", Summary: "remove ports", Safe: true}},
	}
	rep := model.Report{
		Metadata: model.Metadata{Tool: "exposeguard", Version: "test", GeneratedAt: time.Unix(0, 0)},
		Findings: []model.Finding{finding},
	}
	first := BuildSARIF(rep)
	second := BuildSARIF(rep)
	if first.Version != "2.1.0" || first.Schema == "" {
		t.Fatalf("invalid sarif header: %#v", first)
	}
	result := first.Runs[0].Results[0]
	if result.RuleID != "EG-HIGH-006" || result.Level != "error" {
		t.Fatalf("unexpected result mapping: %#v", result)
	}
	if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "docker-compose.yml" {
		t.Fatalf("compose location missing: %#v", result.Locations)
	}
	if result.PartialFingerprints["exposureChain/v1"] == "" || result.PartialFingerprints["exposureChain/v1"] != second.Runs[0].Results[0].PartialFingerprints["exposureChain/v1"] {
		t.Fatalf("fingerprint is not stable: %#v %#v", first, second)
	}
}

func TestSARIFSeverityLevels(t *testing.T) {
	tests := []struct {
		severity model.Severity
		want     string
	}{
		{model.SeverityCritical, "error"},
		{model.SeverityHigh, "error"},
		{model.SeverityMedium, "warning"},
		{model.SeverityLow, "note"},
		{model.SeverityInfo, "note"},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if got := sarifLevel(tt.severity); got != tt.want {
				t.Fatalf("sarifLevel(%s) = %s, want %s", tt.severity, got, tt.want)
			}
		})
	}
}
