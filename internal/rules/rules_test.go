package rules

import (
	"testing"

	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/firewall"
	"github.com/Za1kafps/exposeguard/internal/model"
)

func TestEvaluateDangerousServices(t *testing.T) {
	tests := []struct {
		name         string
		container    docker.Container
		wantSeverity model.Severity
		wantService  string
	}{
		{
			name:         "public postgres is critical",
			container:    containerWithPort("db", "postgres:16", 5432, 5432),
			wantSeverity: model.SeverityCritical,
			wantService:  "postgresql",
		},
		{
			name:         "public grafana is high",
			container:    containerWithPort("grafana", "grafana/grafana", 3000, 3000),
			wantSeverity: model.SeverityHigh,
			wantService:  "grafana",
		},
		{
			name:         "unknown public service is medium",
			container:    containerWithPort("app", "example/app", 8080, 8080),
			wantSeverity: model.SeverityMedium,
			wantService:  "unknown",
		},
		{
			name:         "localhost redis is info",
			container:    containerWithLocalPort("redis", "redis:7", 6379, 6379),
			wantSeverity: model.SeverityInfo,
			wantService:  "redis",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Evaluate(Input{
				Docker:      []docker.Container{tt.container},
				Firewall:    firewall.State{UFWStatus: "inactive"},
				NoListeners: true,
				DockerOK:    true,
			})
			if len(findings) == 0 {
				t.Fatal("expected finding")
			}
			got := findings[0]
			if got.Severity != tt.wantSeverity {
				t.Fatalf("severity = %s, want %s", got.Severity, tt.wantSeverity)
			}
			if got.ServiceName != tt.wantService {
				t.Fatalf("service = %s, want %s", got.ServiceName, tt.wantService)
			}
		})
	}
}

func TestEvaluateComposeHostNetwork(t *testing.T) {
	project := compose.Project{Services: []compose.Service{{Name: "api", Image: "example/api", NetworkMode: "host"}}}
	findings := Evaluate(Input{Compose: &project, NoDocker: true, NoFirewall: true, NoListeners: true})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != model.SeverityMedium {
		t.Fatalf("severity = %s, want medium", findings[0].Severity)
	}
}

func TestEvaluateDockerCompletenessFindings(t *testing.T) {
	tests := []struct {
		name     string
		input    Input
		wantID   string
		notTitle string
	}{
		{
			name:   "docker unavailable is explicit",
			input:  Input{NoFirewall: true, NoListeners: true},
			wantID: "EG-INFO-DOCKER-UNAVAILABLE",
		},
		{
			name:     "no published ports requires successful discovery",
			input:    Input{DockerOK: true, NoFirewall: true, NoListeners: true},
			wantID:   "EG-INFO-DOCKER-NO-PUBLISHED-PORTS",
			notTitle: "Docker discovery is unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Evaluate(tt.input)
			var gotID bool
			for _, finding := range findings {
				if finding.ID == tt.wantID {
					gotID = true
				}
				if tt.notTitle != "" && finding.Title == tt.notTitle {
					t.Fatalf("unexpected finding title %q", tt.notTitle)
				}
			}
			if !gotID {
				t.Fatalf("did not find %s in %#v", tt.wantID, findings)
			}
		})
	}
}

func containerWithPort(name, image string, hostPort, containerPort int) docker.Container {
	return docker.Container{
		Name:  name,
		Image: image,
		PublishedPorts: []docker.PublishedPort{{
			HostIP: "0.0.0.0", HostPort: hostPort, ContainerPort: containerPort, Protocol: "tcp", Binding: model.BindingPublic,
		}},
	}
}

func containerWithLocalPort(name, image string, hostPort, containerPort int) docker.Container {
	container := containerWithPort(name, image, hostPort, containerPort)
	container.PublishedPorts[0].HostIP = "127.0.0.1"
	container.PublishedPorts[0].Binding = model.BindingLocal
	return container
}
