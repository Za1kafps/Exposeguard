package docker

import (
	"context"
	"testing"

	"github.com/Za1kafps/exposeguard/internal/system"
)

func TestParsePortKey(t *testing.T) {
	tests := []struct {
		key       string
		wantPort  int
		wantProto string
		wantErr   bool
	}{
		{key: "5432/tcp", wantPort: 5432, wantProto: "tcp"},
		{key: "53/udp", wantPort: 53, wantProto: "udp"},
		{key: "bad/tcp", wantErr: true},
		{key: "5432", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			port, proto, err := ParsePortKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if port != tt.wantPort || proto != tt.wantProto {
				t.Fatalf("got %d/%s, want %d/%s", port, proto, tt.wantPort, tt.wantProto)
			}
		})
	}
}

func TestDiscoverParsesDockerInspectPorts(t *testing.T) {
	inspect := `[
  {
    "Id": "1234567890abcdef",
    "Name": "/db",
    "Config": {"Image": "postgres:16", "Labels": {"com.example": "test"}},
    "State": {"Status": "running"},
    "HostConfig": {"Binds": ["/data:/data"]},
    "NetworkSettings": {
      "Ports": {
        "5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}],
        "9187/tcp": null
      }
    },
    "Mounts": [{"Type": "bind", "Source": "/data", "Destination": "/data"}]
  }
]`
	runner := system.NewMockRunner(map[string]system.MockResponse{
		system.CommandKey("docker", "ps", "--format", "{{.ID}}"): {
			Result: system.Result{Stdout: "1234567890ab\n"},
		},
		system.CommandKey("docker", "inspect", "1234567890ab"): {
			Result: system.Result{Stdout: inspect},
		},
	})

	result := Discover(context.Background(), runner)
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", result.Warnings)
	}
	if len(result.Containers) != 1 {
		t.Fatalf("got %d containers, want 1", len(result.Containers))
	}
	container := result.Containers[0]
	if container.ID != "1234567890ab" || container.Name != "db" || container.Image != "postgres:16" {
		t.Fatalf("unexpected container: %#v", container)
	}
	if len(container.PublishedPorts) != 1 {
		t.Fatalf("got %d published ports, want 1", len(container.PublishedPorts))
	}
	port := container.PublishedPorts[0]
	if port.HostPort != 5432 || port.ContainerPort != 5432 || port.Protocol != "tcp" {
		t.Fatalf("unexpected port: %#v", port)
	}
	if len(container.ExposedPorts) != 2 {
		t.Fatalf("got %d exposed ports, want 2", len(container.ExposedPorts))
	}
}
