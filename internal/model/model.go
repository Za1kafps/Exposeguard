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
	Metadata Metadata  `json:"metadata"`
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
	Warnings []Warning `json:"warnings,omitempty"`
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

type Finding struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Severity      Severity `json:"severity"`
	ServiceName   string   `json:"service_name,omitempty"`
	ContainerName string   `json:"container_name,omitempty"`
	Image         string   `json:"image,omitempty"`
	Port          int      `json:"port,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	Binding       string   `json:"binding,omitempty"`
	Reason        string   `json:"reason"`
	Impact        string   `json:"impact"`
	Evidence      []string `json:"evidence,omitempty"`
	Fixes         []string `json:"fixes"`
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
