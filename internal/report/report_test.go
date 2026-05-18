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
			Reason: "public binding", Impact: "reachable", Fixes: []string{"bind to localhost"},
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
				Evidence: []string{"long evidence"}, Fixes: []string{"bind to localhost", "remove the port"},
			},
			{ID: "EG-INFO-002", Title: "Firewall state is unknown", Severity: model.SeverityInfo, Fixes: []string{"run as root"}},
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
			Reason: "full reason", Impact: "full impact", Evidence: []string{"full evidence"}, Fixes: []string{"full fix"},
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
