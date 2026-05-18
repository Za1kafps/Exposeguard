package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/model"
	"github.com/Za1kafps/exposeguard/internal/system"
)

type Container struct {
	ID             string
	Name           string
	Image          string
	State          string
	Labels         map[string]string
	PublishedPorts []PublishedPort
	ExposedPorts   []ExposedPort
	Mounts         []Mount
	Binds          []string
}

type PublishedPort struct {
	HostIP        string
	HostPort      int
	ContainerPort int
	Protocol      string
	Binding       model.BindingClass
}

type ExposedPort struct {
	Port     int
	Protocol string
}

type Mount struct {
	Type        string
	Source      string
	Destination string
}

type Result struct {
	Containers []Container
	Warnings   []model.Warning
	Available  bool
}

func Discover(ctx context.Context, runner system.Runner) Result {
	ps, err := runner.Run(ctx, "docker", "ps", "--format", "{{.ID}}")
	if err != nil {
		return Result{Warnings: []model.Warning{{Source: "docker", Message: fmt.Sprintf("Docker is unavailable: %v", err)}}}
	}
	if ps.ExitCode != 0 {
		return Result{Warnings: []model.Warning{{Source: "docker", Message: cleanCommandFailure("docker ps", ps)}}}
	}

	ids := strings.Fields(ps.Stdout)
	if len(ids) == 0 {
		return Result{Available: true}
	}

	args := append([]string{"inspect"}, ids...)
	inspect, err := runner.Run(ctx, "docker", args...)
	if err != nil {
		return Result{Warnings: []model.Warning{{Source: "docker", Message: fmt.Sprintf("docker inspect failed: %v", err)}}}
	}
	if inspect.ExitCode != 0 {
		return Result{Warnings: []model.Warning{{Source: "docker", Message: cleanCommandFailure("docker inspect", inspect)}}}
	}

	containers, err := parseInspect(inspect.Stdout)
	if err != nil {
		return Result{Warnings: []model.Warning{{Source: "docker", Message: fmt.Sprintf("docker inspect output could not be parsed: %v", err)}}}
	}
	return Result{Containers: containers, Available: true}
}

func parseInspect(data string) ([]Container, error) {
	var inspected []inspectContainer
	if err := json.Unmarshal([]byte(data), &inspected); err != nil {
		return nil, err
	}

	containers := make([]Container, 0, len(inspected))
	for _, item := range inspected {
		container := Container{
			ID:     shortID(item.ID),
			Name:   strings.TrimPrefix(item.Name, "/"),
			Image:  item.Config.Image,
			State:  item.State.Status,
			Labels: item.Config.Labels,
			Binds:  append([]string(nil), item.HostConfig.Binds...),
		}
		for _, mount := range item.Mounts {
			container.Mounts = append(container.Mounts, Mount{
				Type:        mount.Type,
				Source:      mount.Source,
				Destination: mount.Destination,
			})
		}
		for key, bindings := range item.NetworkSettings.Ports {
			port, proto, err := ParsePortKey(key)
			if err != nil {
				continue
			}
			container.ExposedPorts = append(container.ExposedPorts, ExposedPort{Port: port, Protocol: proto})
			for _, binding := range bindings {
				hostPort, err := strconv.Atoi(binding.HostPort)
				if err != nil {
					continue
				}
				container.PublishedPorts = append(container.PublishedPorts, PublishedPort{
					HostIP:        normalizeHostIP(binding.HostIP),
					HostPort:      hostPort,
					ContainerPort: port,
					Protocol:      proto,
					Binding:       model.ClassifyBinding(binding.HostIP),
				})
			}
		}
		containers = append(containers, container)
	}
	return containers, nil
}

func ParsePortKey(key string) (int, string, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid docker port key %q", key)
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid docker port %q: %w", parts[0], err)
	}
	return port, strings.ToLower(parts[1]), nil
}

func HasDockerSocket(container Container) bool {
	for _, bind := range container.Binds {
		if strings.Contains(bind, "/var/run/docker.sock") {
			return true
		}
	}
	for _, mount := range container.Mounts {
		if mount.Source == "/var/run/docker.sock" || mount.Destination == "/var/run/docker.sock" {
			return true
		}
	}
	return false
}

func normalizeHostIP(hostIP string) string {
	if strings.TrimSpace(hostIP) == "" {
		return "0.0.0.0"
	}
	return hostIP
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func cleanCommandFailure(command string, result system.Result) string {
	detail := strings.TrimSpace(result.Stderr)
	if detail == "" {
		detail = strings.TrimSpace(result.Stdout)
	}
	if detail == "" {
		detail = fmt.Sprintf("exit code %d", result.ExitCode)
	}
	detail = firstLine(detail)
	return fmt.Sprintf("%s failed: %s", command, detail)
}

func firstLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 240 {
			return line[:240] + "..."
		}
		return line
	}
	return value
}

type inspectContainer struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status string `json:"Status"`
	} `json:"State"`
	HostConfig struct {
		Binds []string `json:"Binds"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}
