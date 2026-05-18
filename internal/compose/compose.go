package compose

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Project struct {
	Path     string
	Services []Service
}

type Service struct {
	Name            string
	Image           string
	Ports           []string
	Expose          []string
	NetworkMode     string
	Privileged      bool
	Volumes         []string
	EnvironmentKeys []string
	Labels          map[string]string
}

func ParseFile(path string) (Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Project{}, fmt.Errorf("read compose file: %w", err)
	}
	var raw composeFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Project{}, fmt.Errorf("parse compose file: %w", err)
	}
	project := Project{Path: path}
	for name, service := range raw.Services {
		project.Services = append(project.Services, Service{
			Name:            name,
			Image:           service.Image,
			Ports:           stringList(service.Ports),
			Expose:          stringList(service.Expose),
			NetworkMode:     scalarString(service.NetworkMode),
			Privileged:      service.Privileged,
			Volumes:         stringList(service.Volumes),
			EnvironmentKeys: environmentKeys(service.Environment),
			Labels:          labels(service.Labels),
		})
	}
	sort.Slice(project.Services, func(i, j int) bool {
		return project.Services[i].Name < project.Services[j].Name
	})
	return project, nil
}

func stringList(node yaml.Node) []string {
	switch node.Kind {
	case yaml.SequenceNode:
		var values []string
		for _, item := range node.Content {
			values = append(values, scalarString(*item))
		}
		return values
	case yaml.ScalarNode, yaml.MappingNode:
		value := scalarString(node)
		if value == "" {
			return nil
		}
		return []string{value}
	default:
		return nil
	}
}

func scalarString(node yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value
	case yaml.MappingNode:
		var parts []string
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			value := scalarString(*node.Content[i+1])
			if value == "" {
				parts = append(parts, key)
			} else {
				parts = append(parts, key+"="+value)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func environmentKeys(node yaml.Node) []string {
	keys := map[string]struct{}{}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			keys[node.Content[i].Value] = struct{}{}
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			value := scalarString(*item)
			key := value
			if before, _, ok := strings.Cut(value, "="); ok {
				key = before
			}
			if key != "" {
				keys[key] = struct{}{}
			}
		}
	}
	return sortedKeys(keys)
}

func labels(node yaml.Node) map[string]string {
	values := map[string]string{}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			values[node.Content[i].Value] = scalarString(*node.Content[i+1])
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			value := scalarString(*item)
			if before, after, ok := strings.Cut(value, "="); ok {
				values[before] = after
			} else if value != "" {
				values[value] = ""
			}
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Image       string    `yaml:"image"`
	Ports       yaml.Node `yaml:"ports"`
	Expose      yaml.Node `yaml:"expose"`
	NetworkMode yaml.Node `yaml:"network_mode"`
	Privileged  bool      `yaml:"privileged"`
	Volumes     yaml.Node `yaml:"volumes"`
	Environment yaml.Node `yaml:"environment"`
	Labels      yaml.Node `yaml:"labels"`
}

func ParsePublishedPort(value string) (hostIP string, hostPort int, containerPort int, protocol string, ok bool) {
	protocol = "tcp"
	portSpec, proto, hasProto := strings.Cut(value, "/")
	if hasProto {
		protocol = strings.ToLower(proto)
	}
	parts := strings.Split(portSpec, ":")
	if len(parts) == 1 {
		containerPort, ok = atoi(parts[0])
		return "", containerPort, containerPort, protocol, ok
	}
	if len(parts) == 2 {
		hostPort, hostOK := atoi(parts[0])
		containerPort, containerOK := atoi(parts[1])
		return "", hostPort, containerPort, protocol, hostOK && containerOK
	}
	if len(parts) >= 3 {
		hostIP = strings.Join(parts[:len(parts)-2], ":")
		hostPort, hostOK := atoi(parts[len(parts)-2])
		containerPort, containerOK := atoi(parts[len(parts)-1])
		return hostIP, hostPort, containerPort, protocol, hostOK && containerOK
	}
	return "", 0, 0, protocol, false
}

func atoi(value string) (int, bool) {
	value = strings.Trim(value, `"`)
	i, err := strconv.Atoi(value)
	return i, err == nil
}
