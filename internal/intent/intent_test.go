package intent

import (
	"testing"

	"github.com/Za1kafps/exposeguard/internal/compose"
)

func TestInferComposeIntent(t *testing.T) {
	tests := []struct {
		name    string
		service compose.Service
		port    int
		want    string
	}{
		{name: "database", service: compose.Service{Name: "db", Image: "postgres:16", EnvironmentKeys: []string{"POSTGRES_PASSWORD"}}, port: 5432, want: "database"},
		{name: "cache", service: compose.Service{Name: "redis", Image: "redis:7"}, port: 6379, want: "cache"},
		{name: "dashboard", service: compose.Service{Name: "grafana", Image: "grafana/grafana"}, port: 3000, want: "dashboard"},
		{name: "reverse proxy", service: compose.Service{Name: "traefik", Image: "traefik:v3", Ports: []string{"80:80"}, Labels: map[string]string{"traefik.enable": "true"}}, port: 80, want: "reverse-proxy"},
		{name: "internal api", service: compose.Service{Name: "backend-api", Image: "example/api"}, port: 8080, want: "internal-api"},
		{name: "unknown", service: compose.Service{Name: "thing", Image: "example/custom"}, port: 12345, want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Infer(Input{Compose: &tt.service, HostPort: tt.port, ContainerPort: tt.port})
			if got.Category != tt.want {
				t.Fatalf("category = %q, want %q; signals=%v", got.Category, tt.want, got.Signals)
			}
			if got.Confidence == "" {
				t.Fatal("confidence is empty")
			}
		})
	}
}
