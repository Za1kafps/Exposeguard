package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/firewall"
	"github.com/Za1kafps/exposeguard/internal/listener"
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

func TestExposureChainConstruction(t *testing.T) {
	project := compose.Project{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "db", Image: "postgres:16", Ports: []string{"5432:5432"}, Networks: []string{"internal"}, EnvironmentKeys: []string{"POSTGRES_PASSWORD"},
		}},
	}
	container := containerWithPort("project-db-1", "postgres:16", 5432, 5432)
	container.Labels = map[string]string{"com.docker.compose.service": "db"}
	container.Networks = []string{"internal"}
	findings := Evaluate(Input{
		Docker:    []docker.Container{container},
		Compose:   &project,
		Firewall:  firewall.State{UFWStatus: "active", HasDockerChain: true},
		Listeners: []listener.Listener{{Protocol: "tcp", LocalIP: "0.0.0.0", Port: 5432, Process: "docker-proxy", Binding: model.BindingPublic}},
		DockerOK:  true,
	})
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	got := findings[0]
	if got.Compose == nil || got.Container == nil || got.PublishedPort == nil {
		t.Fatalf("chain is incomplete: %#v", got)
	}
	if got.Compose.ServiceName != "db" || got.Container.Name != "project-db-1" || got.PublishedPort.HostPort != 5432 {
		t.Fatalf("unexpected chain endpoints: %#v", got)
	}
	if len(got.Firewall) == 0 || len(got.Listener) == 0 {
		t.Fatalf("expected firewall and listener evidence: %#v", got.Evidence)
	}
	if got.Intent.Category != "database" {
		t.Fatalf("intent = %q, want database", got.Intent.Category)
	}
	if len(got.Fixes) == 0 {
		t.Fatal("expected fixes")
	}
}

func TestReverseProxyBypassDetection(t *testing.T) {
	project := compose.Project{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "proxy", Image: "traefik:v3", Ports: []string{"80:80", "443:443"}, Networks: []string{"edge"}},
			{Name: "api", Image: "example/backend-api", Ports: []string{"0.0.0.0:3000:3000"}, Expose: []string{"3000"}, Networks: []string{"edge"}},
		},
	}
	api := containerWithPort("project-api-1", "example/backend-api", 3000, 3000)
	api.Labels = map[string]string{"com.docker.compose.service": "api"}
	api.Networks = []string{"edge"}
	findings := Evaluate(Input{
		Docker:      []docker.Container{api},
		Compose:     &project,
		Firewall:    firewall.State{UFWStatus: "inactive"},
		NoListeners: true,
		DockerOK:    true,
	})
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].RuleID != RuleReverseProxyBypass {
		t.Fatalf("rule = %q, want %q: %#v", findings[0].RuleID, RuleReverseProxyBypass, findings[0])
	}
	if findings[0].ReverseProxy == nil || findings[0].ReverseProxy.ServiceName != "proxy" {
		t.Fatalf("reverse proxy evidence missing: %#v", findings[0].ReverseProxy)
	}
}

func TestNoEnvironmentValuesLeaked(t *testing.T) {
	project := compose.Project{Path: "docker-compose.yml", Services: []compose.Service{{
		Name: "db", Image: "postgres:16", Ports: []string{"5432:5432"}, EnvironmentKeys: []string{"POSTGRES_PASSWORD"}, Labels: map[string]string{"app.password": "supersecret"},
	}}}
	container := containerWithPort("db", "postgres:16", 5432, 5432)
	container.Labels = map[string]string{"com.docker.compose.service": "db", "secret.label": "supersecret"}
	findings := Evaluate(Input{Docker: []docker.Container{container}, Compose: &project, Firewall: firewall.State{UFWStatus: "inactive"}, NoListeners: true, DockerOK: true})
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "supersecret") {
		t.Fatalf("secret value leaked in report: %s", text)
	}
	if !strings.Contains(text, "POSTGRES_PASSWORD") {
		t.Fatalf("environment key missing from report: %s", text)
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
			wantID: RuleDockerUnavailable,
		},
		{
			name:     "no published ports requires successful discovery",
			input:    Input{DockerOK: true, NoFirewall: true, NoListeners: true},
			wantID:   RuleNoPublishedPorts,
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
