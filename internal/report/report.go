package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/model"
)

type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
)

type RenderOptions struct {
	Verbose    bool
	DetailHint string
}

func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "terminal":
		return FormatTerminal, nil
	case "json":
		return FormatJSON, nil
	case "markdown":
		return FormatMarkdown, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("invalid report format %q", value)
	}
}

func Render(format Format, report model.Report) ([]byte, error) {
	return RenderWithOptions(format, report, RenderOptions{Verbose: true})
}

func RenderWithOptions(format Format, report model.Report, options RenderOptions) ([]byte, error) {
	switch format {
	case FormatTerminal:
		return []byte(RenderTerminal(report, options)), nil
	case FormatJSON:
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	case FormatMarkdown:
		return []byte(RenderMarkdown(report)), nil
	case FormatSARIF:
		data, err := json.MarshalIndent(BuildSARIF(report), "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func RenderTerminal(report model.Report, options RenderOptions) string {
	if !options.Verbose {
		return RenderTerminalConcise(report, options.DetailHint)
	}
	return RenderTerminalDetailed(report)
}

func RenderTerminalConcise(report model.Report, detailHint string) string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "ExposeGuard scan report\n")
	fmt.Fprintf(&out, "Generated: %s\n", report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&out, "Summary: %d findings (%d critical, %d high, %d medium, %d low, %d info)\n",
		report.Summary.Total, report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Low, report.Summary.Info)
	fmt.Fprintf(&out, "Scan status: %s\n\n", scanStatus(report))

	important := importantTerminalFindings(report.Findings)
	if len(important) == 0 {
		fmt.Fprintf(&out, "No critical, high or medium findings were found.\n\n")
	} else {
		for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium} {
			group := findingsBySeverity(important, severity)
			if len(group) == 0 {
				continue
			}
			fmt.Fprintf(&out, "%s\n", strings.ToUpper(string(severity)))
			for _, finding := range group {
				fmt.Fprintf(&out, "  %s %s\n", finding.ID, finding.Title)
				if finding.ContainerName != "" || finding.Image != "" {
					fmt.Fprintf(&out, "    Target: %s %s\n", finding.ContainerName, finding.Image)
				}
				if finding.Binding != "" {
					fmt.Fprintf(&out, "    Binding: %s/%s\n", finding.Binding, finding.Protocol)
				}
				if len(finding.Fixes) > 0 {
					fmt.Fprintf(&out, "    Fix: %s\n", finding.Fixes[0].Summary)
				}
				fmt.Fprintf(&out, "    Chain: %s\n", chainSummary(finding))
				fmt.Fprintf(&out, "\n")
			}
		}
	}

	if len(report.Warnings) > 0 {
		fmt.Fprintf(&out, "Incomplete checks: %d diagnostic warning(s) hidden in concise output.\n", len(report.Warnings))
	}
	hidden := hiddenFindingCount(report.Findings)
	if hidden > 0 {
		fmt.Fprintf(&out, "Additional details: %d low/info finding(s) hidden in concise output.\n", hidden)
	}
	if (len(report.Warnings) > 0 || hidden > 0) && detailHint != "" {
		fmt.Fprintf(&out, "\nMore details:\n")
		fmt.Fprintf(&out, "  %s\n", detailHint)
	}
	return out.String()
}

func RenderTerminalDetailed(report model.Report) string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "ExposeGuard scan report\n")
	fmt.Fprintf(&out, "Generated: %s\n", report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&out, "Summary: %d findings (%d critical, %d high, %d medium, %d low, %d info)\n\n",
		report.Summary.Total, report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Low, report.Summary.Info)

	if len(report.Warnings) > 0 {
		fmt.Fprintf(&out, "Warnings\n")
		for _, warning := range report.Warnings {
			fmt.Fprintf(&out, "  - [%s] %s\n", warning.Source, warning.Message)
		}
		fmt.Fprintf(&out, "\n")
	}

	if len(report.Findings) == 0 {
		fmt.Fprintf(&out, "No findings.\n")
		return out.String()
	}

	for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		group := findingsBySeverity(report.Findings, severity)
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&out, "%s\n", strings.ToUpper(string(severity)))
		for _, finding := range group {
			fmt.Fprintf(&out, "  %s %s\n", finding.ID, finding.Title)
			if finding.ContainerName != "" || finding.Image != "" {
				fmt.Fprintf(&out, "    Target: %s %s\n", finding.ContainerName, finding.Image)
			}
			if finding.Binding != "" {
				fmt.Fprintf(&out, "    Binding: %s/%s\n", finding.Binding, finding.Protocol)
			}
			fmt.Fprintf(&out, "    Intent: %s (%s)\n", emptyDefault(finding.Intent.Category, "unknown"), emptyDefault(finding.Intent.Confidence, "low"))
			if chain := chainSummary(finding); chain != "" {
				fmt.Fprintf(&out, "    Chain: %s\n", chain)
			}
			fmt.Fprintf(&out, "    Reason: %s\n", finding.Reason)
			fmt.Fprintf(&out, "    Impact: %s\n", finding.Impact)
			if len(finding.Evidence) > 0 {
				fmt.Fprintf(&out, "    Evidence:\n")
				for _, item := range finding.Evidence {
					fmt.Fprintf(&out, "      - [%s/%s] %s\n", item.Source, emptyDefault(item.Confidence, "unknown"), item.Summary)
					if len(item.Details) > 0 {
						for _, key := range sortedDetailKeys(item.Details) {
							fmt.Fprintf(&out, "        %s: %s\n", key, item.Details[key])
						}
					}
				}
			}
			if len(finding.Fixes) > 0 {
				fmt.Fprintf(&out, "    Fixes:\n")
				for _, fix := range finding.Fixes {
					fmt.Fprintf(&out, "      - %s: %s\n", fix.Title, fix.Summary)
					if fix.ComposePatchHint != "" {
						fmt.Fprintf(&out, "        Compose hint: %s\n", oneLine(fix.ComposePatchHint))
					}
					for _, command := range fix.Commands {
						fmt.Fprintf(&out, "        Command: %s\n", command)
					}
					for _, warning := range fix.Warnings {
						fmt.Fprintf(&out, "        Warning: %s\n", warning)
					}
				}
			}
			fmt.Fprintf(&out, "\n")
		}
	}
	return out.String()
}

func scanStatus(report model.Report) string {
	if len(report.Warnings) > 0 {
		return "incomplete; some checks could not run"
	}
	if report.Summary.Critical > 0 || report.Summary.High > 0 || report.Summary.Medium > 0 {
		return "completed with findings"
	}
	return "completed; no critical, high or medium findings"
}

func importantTerminalFindings(findings []model.Finding) []model.Finding {
	var important []model.Finding
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium:
			important = append(important, finding)
		}
	}
	return important
}

func hiddenFindingCount(findings []model.Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == model.SeverityLow || finding.Severity == model.SeverityInfo {
			count++
		}
	}
	return count
}

func RenderMarkdown(report model.Report) string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "# ExposeGuard scan report\n\n")
	fmt.Fprintf(&out, "- Generated: `%s`\n", report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&out, "- Hostname: `%s`\n\n", emptyDefault(report.Metadata.Hostname, "unknown"))

	fmt.Fprintf(&out, "## Summary\n\n")
	fmt.Fprintf(&out, "| Severity | Count |\n")
	fmt.Fprintf(&out, "| --- | ---: |\n")
	fmt.Fprintf(&out, "| Critical | %d |\n", report.Summary.Critical)
	fmt.Fprintf(&out, "| High | %d |\n", report.Summary.High)
	fmt.Fprintf(&out, "| Medium | %d |\n", report.Summary.Medium)
	fmt.Fprintf(&out, "| Low | %d |\n", report.Summary.Low)
	fmt.Fprintf(&out, "| Info | %d |\n\n", report.Summary.Info)

	if len(report.Warnings) > 0 {
		fmt.Fprintf(&out, "## Warnings\n\n")
		for _, warning := range report.Warnings {
			fmt.Fprintf(&out, "- `%s`: %s\n", warning.Source, warning.Message)
		}
		fmt.Fprintf(&out, "\n")
	}

	fmt.Fprintf(&out, "## Findings\n\n")
	if len(report.Findings) == 0 {
		fmt.Fprintf(&out, "No findings.\n")
		return out.String()
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(&out, "### %s: %s\n\n", finding.ID, finding.Title)
		fmt.Fprintf(&out, "- Severity: `%s`\n", finding.Severity)
		if finding.ContainerName != "" {
			fmt.Fprintf(&out, "- Container: `%s`\n", finding.ContainerName)
		}
		if finding.Image != "" {
			fmt.Fprintf(&out, "- Image: `%s`\n", finding.Image)
		}
		if finding.Binding != "" {
			fmt.Fprintf(&out, "- Binding: `%s/%s`\n", finding.Binding, finding.Protocol)
		}
		if finding.Intent.Category != "" {
			fmt.Fprintf(&out, "- Intent: `%s` (`%s` confidence)\n", finding.Intent.Category, emptyDefault(finding.Intent.Confidence, "low"))
		}
		if chain := chainSummary(finding); chain != "" {
			fmt.Fprintf(&out, "- Chain: %s\n", chain)
		}
		fmt.Fprintf(&out, "- Reason: %s\n", finding.Reason)
		fmt.Fprintf(&out, "- Impact: %s\n\n", finding.Impact)
		if len(finding.Evidence) > 0 {
			fmt.Fprintf(&out, "Evidence:\n\n")
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(&out, "- `%s` (`%s`): %s\n", evidence.Source, emptyDefault(evidence.Confidence, "unknown"), evidence.Summary)
			}
			fmt.Fprintf(&out, "\n")
		}
		if len(finding.Fixes) > 0 {
			fmt.Fprintf(&out, "Fix suggestions:\n\n")
			for _, fix := range finding.Fixes {
				fmt.Fprintf(&out, "- **%s:** %s\n", fix.Title, fix.Summary)
				if fix.ComposePatchHint != "" {
					fmt.Fprintf(&out, "\n```yaml\n%s\n```\n\n", fix.ComposePatchHint)
				}
				if len(fix.Commands) > 0 {
					fmt.Fprintf(&out, "\n```sh\n")
					for _, command := range fix.Commands {
						fmt.Fprintf(&out, "%s\n", command)
					}
					fmt.Fprintf(&out, "```\n\n")
				}
			}
			fmt.Fprintf(&out, "\n")
		}
	}
	return out.String()
}

type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription SARIFText       `json:"shortDescription"`
	FullDescription  SARIFText       `json:"fullDescription,omitempty"`
	Properties       SARIFProperties `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SARIFText         `json:"message"`
	Locations           []SARIFLocation   `json:"locations,omitempty"`
	Properties          SARIFProperties   `json:"properties,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type SARIFProperties map[string]interface{}

func BuildSARIF(report model.Report) SARIFLog {
	rules := map[string]SARIFRule{}
	var results []SARIFResult
	for _, finding := range report.Findings {
		ruleID := finding.RuleID
		if ruleID == "" {
			ruleID = finding.ID
		}
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = SARIFRule{
				ID:               ruleID,
				Name:             ruleName(ruleID),
				ShortDescription: SARIFText{Text: finding.Title},

				FullDescription: SARIFText{Text: finding.Impact},
				Properties:      SARIFProperties{"severity": string(finding.Severity)},
			}
		}
		results = append(results, SARIFResult{
			RuleID:              ruleID,
			Level:               sarifLevel(finding.Severity),
			Message:             SARIFText{Text: sarifMessage(finding)},
			Locations:           sarifLocations(finding),
			Properties:          sarifProperties(finding),
			PartialFingerprints: map[string]string{"exposureChain/v1": stableFingerprint(finding)},
		})
	}
	return SARIFLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:            "ExposeGuard",
				SemanticVersion: report.Metadata.Version,
				Rules:           sortedSARIFRules(rules),
			}},
			Results: results,
		}},
	}
}

func sarifMessage(finding model.Finding) string {
	parts := []string{finding.Reason, finding.Impact}
	if len(finding.Fixes) > 0 {
		parts = append(parts, "Fix: "+finding.Fixes[0].Summary)
	}
	return strings.Join(nonEmpty(parts), " ")
}

func sarifProperties(finding model.Finding) SARIFProperties {
	props := SARIFProperties{
		"severity":   string(finding.Severity),
		"intent":     finding.Intent.Category,
		"confidence": finding.Intent.Confidence,
	}
	if finding.ServiceName != "" {
		props["serviceName"] = finding.ServiceName
	}
	if finding.ContainerName != "" {
		props["containerName"] = finding.ContainerName
	}
	if finding.PublishedPort != nil {
		props["hostPort"] = finding.PublishedPort.HostPort
		props["containerPort"] = finding.PublishedPort.ContainerPort
		props["binding"] = model.BindingDescription(finding.PublishedPort.HostIP, finding.PublishedPort.HostPort)
	} else if finding.Port != 0 {
		props["hostPort"] = finding.Port
		props["binding"] = finding.Binding
	}
	return props
}

func sarifLocations(finding model.Finding) []SARIFLocation {
	if finding.Compose == nil || finding.Compose.File == "" {
		return nil
	}
	return []SARIFLocation{{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{URI: finding.Compose.File},
			Region:           SARIFRegion{StartLine: 1},
		},
	}}
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func stableFingerprint(finding model.Finding) string {
	values := []string{finding.ID, finding.ServiceName, finding.ContainerName, finding.Binding, finding.Protocol, finding.RuleID}
	if finding.PublishedPort != nil {
		values = append(values,
			fmt.Sprintf("%d", finding.PublishedPort.HostPort),
			fmt.Sprintf("%d", finding.PublishedPort.ContainerPort),
		)
	} else {
		values = append(values, fmt.Sprintf("%d", finding.Port))
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "|")))
	return fmt.Sprintf("%x", sum[:])
}

func sortedSARIFRules(values map[string]SARIFRule) []SARIFRule {
	rules := make([]SARIFRule, 0, len(values))
	for _, rule := range values {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func ruleName(ruleID string) string {
	names := map[string]string{
		"EG-CRITICAL-001": "public-postgresql",
		"EG-CRITICAL-002": "public-mysql-mariadb",
		"EG-CRITICAL-003": "public-redis",
		"EG-CRITICAL-004": "public-mongodb",
		"EG-CRITICAL-005": "public-docker-daemon",
		"EG-HIGH-001":     "public-admin-dashboard",
		"EG-HIGH-002":     "public-portainer",
		"EG-HIGH-003":     "public-grafana",
		"EG-HIGH-004":     "public-prometheus",
		"EG-HIGH-005":     "docker-socket-dashboard",
		"EG-HIGH-006":     "reverse-proxy-bypass",
		"EG-MEDIUM-001":   "unknown-public-service",
		"EG-MEDIUM-002":   "host-network-mode",
		"EG-MEDIUM-003":   "direct-http-without-proxy-context",
		"EG-INFO-001":     "localhost-only-binding",
		"EG-INFO-002":     "no-published-docker-ports",
		"EG-INFO-003":     "firewall-state-unknown",
	}
	if name := names[ruleID]; name != "" {
		return name
	}
	return strings.ToLower(ruleID)
}

func findingsBySeverity(findings []model.Finding, severity model.Severity) []model.Finding {
	var group []model.Finding
	for _, finding := range findings {
		if finding.Severity == severity {
			group = append(group, finding)
		}
	}
	sort.SliceStable(group, func(i, j int) bool {
		return group[i].ID < group[j].ID
	})
	return group
}

func emptyDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func chainSummary(finding model.Finding) string {
	parts := []string{}
	if finding.Compose != nil && finding.Compose.ServiceName != "" {
		parts = append(parts, "compose "+finding.Compose.ServiceName)
	}
	if finding.ContainerName != "" {
		parts = append(parts, "container "+finding.ContainerName)
	}
	if finding.PublishedPort != nil {
		parts = append(parts, fmt.Sprintf("published %s:%d->%d/%s", emptyDefault(finding.PublishedPort.HostIP, "0.0.0.0"), finding.PublishedPort.HostPort, finding.PublishedPort.ContainerPort, finding.PublishedPort.Protocol))
	} else if finding.Binding != "" {
		parts = append(parts, "binding "+finding.Binding)
	}
	if len(finding.Firewall) > 0 {
		parts = append(parts, "firewall evidence")
	}
	if len(finding.Listener) > 0 {
		parts = append(parts, "listener evidence")
	}
	if finding.Intent.Category != "" {
		parts = append(parts, "risk "+finding.Intent.Category)
	}
	return strings.Join(parts, " -> ")
}

func sortedDetailKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func nonEmpty(values []string) []string {
	var out []string
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}
