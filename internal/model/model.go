package model

import (
	"fmt"
	"strings"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

var severityRank = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
	SeverityInfo:     0,
}

func ParseSeverity(value string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "info":
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("unknown severity %q", value)
	}
}

func SeverityAtLeast(got, threshold Severity) bool {
	return severityRank[got] >= severityRank[threshold]
}

type FailThreshold string

const (
	FailCritical FailThreshold = "critical"
	FailHigh     FailThreshold = "high"
	FailMedium   FailThreshold = "medium"
	FailLow      FailThreshold = "low"
	FailNone     FailThreshold = "none"
)

func ParseFailThreshold(value string) (FailThreshold, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return FailCritical, nil
	case "high":
		return FailHigh, nil
	case "medium":
		return FailMedium, nil
	case "low":
		return FailLow, nil
	case "none":
		return FailNone, nil
	default:
		return "", fmt.Errorf("invalid fail threshold %q", value)
	}
}

func FailsThreshold(findings []Finding, threshold FailThreshold) bool {
	if threshold == FailNone {
		return false
	}
	minSeverity, _ := ParseSeverity(string(threshold))
	for _, finding := range findings {
		if SeverityAtLeast(finding.Severity, minSeverity) {
			return true
		}
	}
	return false
}

type Metadata struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Hostname    string    `json:"hostname,omitempty"`
}

type Report struct {
	Metadata     Metadata            `json:"metadata"`
	Summary      Summary             `json:"summary"`
	Findings     []Finding           `json:"findings"`
	Warnings     []Warning           `json:"warnings,omitempty"`
	Capabilities ScannerCapabilities `json:"scanner_capabilities"`
}

type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type Warning struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

type ScannerCapabilities struct {
	Docker    bool `json:"docker"`
	Compose   bool `json:"compose"`
	Firewall  bool `json:"firewall"`
	Listeners bool `json:"listeners"`
}

type Finding = ExposureChain

type ExposureChain struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`

	Compose       *ComposeEvidence       `json:"compose,omitempty"`
	Container     *ContainerEvidence     `json:"container,omitempty"`
	PublishedPort *PublishedPortEvidence `json:"published_port,omitempty"`
	Firewall      []Evidence             `json:"firewall,omitempty"`
	Listener      []Evidence             `json:"listener,omitempty"`

	Intent       ServiceIntent         `json:"intent"`
	ReverseProxy *ReverseProxyEvidence `json:"reverse_proxy,omitempty"`

	ServiceName   string `json:"service_name,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Image         string `json:"image,omitempty"`
	Port          int    `json:"port,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Binding       string `json:"binding,omitempty"`

	Reason   string     `json:"reason"`
	Impact   string     `json:"impact"`
	Fixes    []Fix      `json:"fixes"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

type ComposeEvidence struct {
	File            string            `json:"file,omitempty"`
	ServiceName     string            `json:"service_name,omitempty"`
	Image           string            `json:"image,omitempty"`
	Ports           []string          `json:"ports,omitempty"`
	Expose          []string          `json:"expose,omitempty"`
	Networks        []string          `json:"networks,omitempty"`
	NetworkMode     string            `json:"network_mode,omitempty"`
	Privileged      bool              `json:"privileged,omitempty"`
	Volumes         []string          `json:"volumes,omitempty"`
	EnvironmentKeys []string          `json:"environment_keys,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Command         string            `json:"command,omitempty"`
	Healthcheck     string            `json:"healthcheck,omitempty"`
}

type ContainerEvidence struct {
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name,omitempty"`
	Image    string            `json:"image,omitempty"`
	State    string            `json:"state,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Networks []string          `json:"networks,omitempty"`
	Mounts   []string          `json:"mounts,omitempty"`
}

type PublishedPortEvidence struct {
	HostIP        string       `json:"host_ip,omitempty"`
	HostPort      int          `json:"host_port,omitempty"`
	ContainerPort int          `json:"container_port,omitempty"`
	Protocol      string       `json:"protocol,omitempty"`
	Binding       BindingClass `json:"binding_class,omitempty"`
}

type Evidence struct {
	Source     string            `json:"source"`
	Summary    string            `json:"summary"`
	Details    map[string]string `json:"details,omitempty"`
	Confidence string            `json:"confidence"`
}

type Fix struct {
	Title            string   `json:"title"`
	Summary          string   `json:"summary"`
	ComposePatchHint string   `json:"compose_patch_hint,omitempty"`
	Commands         []string `json:"commands,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	Safe             bool     `json:"safe"`
}

type ServiceIntent struct {
	Category   string   `json:"category"`
	Confidence string   `json:"confidence"`
	Signals    []string `json:"signals,omitempty"`
}

type ReverseProxyEvidence struct {
	Present        bool       `json:"present"`
	ServiceName    string     `json:"service_name,omitempty"`
	ContainerName  string     `json:"container_name,omitempty"`
	Image          string     `json:"image,omitempty"`
	Networks       []string   `json:"networks,omitempty"`
	PublishedPorts []int      `json:"published_ports,omitempty"`
	Evidence       []Evidence `json:"evidence,omitempty"`
}

func BuildSummary(findings []Finding) Summary {
	summary := Summary{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		case SeverityInfo:
			summary.Info++
		}
	}
	return summary
}

type BindingClass string

const (
	BindingPublic  BindingClass = "public"
	BindingLocal   BindingClass = "local"
	BindingUnknown BindingClass = "unknown"
)

func ClassifyBinding(hostIP string) BindingClass {
	hostIP = strings.TrimSpace(hostIP)
	hostIP = strings.Trim(hostIP, "[]")
	switch strings.ToLower(hostIP) {
	case "", "0.0.0.0", "::", "*":
		return BindingPublic
	case "localhost", "127.0.0.1", "::1":
		return BindingLocal
	}
	if strings.HasPrefix(hostIP, "127.") {
		return BindingLocal
	}
	return BindingPublic
}

func BindingDescription(hostIP string, port int) string {
	if strings.TrimSpace(hostIP) == "" {
		hostIP = "0.0.0.0"
	}
	if port > 0 {
		return fmt.Sprintf("%s:%d", hostIP, port)
	}
	return hostIP
}
