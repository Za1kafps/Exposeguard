package fixes

import (
	"strings"
	"testing"

	"github.com/Za1kafps/exposeguard/internal/model"
)

func TestGenerateComposeAwareFixes(t *testing.T) {
	tests := []struct {
		name     string
		input    Input
		wantText string
	}{
		{
			name:     "public database",
			input:    Input{Intent: model.ServiceIntent{Category: "database"}, HostPort: 5432, ContainerPort: 5432, Protocol: "tcp", HasCompose: true},
			wantText: "Remove the public port",
		},
		{
			name:     "dashboard",
			input:    Input{Intent: model.ServiceIntent{Category: "dashboard"}, HostPort: 3000, ContainerPort: 3000, Protocol: "tcp", HasCompose: true},
			wantText: "protected reverse proxy",
		},
		{
			name:     "internal api behind proxy",
			input:    Input{Intent: model.ServiceIntent{Category: "internal-api"}, RuleID: "EG-HIGH-006", HostPort: 8080, ContainerPort: 8080, Protocol: "tcp", HasCompose: true, BehindProxy: true},
			wantText: "Remove backend ports",
		},
		{
			name:     "unknown service",
			input:    Input{Intent: model.ServiceIntent{Category: "unknown"}, HostPort: 12345, ContainerPort: 12345, Protocol: "tcp", HasCompose: true},
			wantText: "local-only",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixes := Generate(tt.input)
			var joined []string
			for _, fix := range fixes {
				joined = append(joined, fix.Title, fix.Summary, fix.ComposePatchHint)
				if !fix.Safe {
					t.Fatalf("fix is not marked safe: %#v", fix)
				}
			}
			if !strings.Contains(strings.Join(joined, "\n"), tt.wantText) {
				t.Fatalf("fixes do not contain %q: %#v", tt.wantText, fixes)
			}
		})
	}
}
