package report

import (
	"bytes"
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
					fmt.Fprintf(&out, "    Fix: %s\n", finding.Fixes[0])
				}
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
			fmt.Fprintf(&out, "    Reason: %s\n", finding.Reason)
			fmt.Fprintf(&out, "    Impact: %s\n", finding.Impact)
			if len(finding.Evidence) > 0 {
				fmt.Fprintf(&out, "    Evidence:\n")
				for _, item := range finding.Evidence {
					fmt.Fprintf(&out, "      - %s\n", item)
				}
			}
			if len(finding.Fixes) > 0 {
				fmt.Fprintf(&out, "    Fixes:\n")
				for _, fix := range finding.Fixes {
					fmt.Fprintf(&out, "      - %s\n", fix)
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
		fmt.Fprintf(&out, "- Reason: %s\n", finding.Reason)
		fmt.Fprintf(&out, "- Impact: %s\n\n", finding.Impact)
		if len(finding.Evidence) > 0 {
			fmt.Fprintf(&out, "Evidence:\n\n")
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(&out, "- %s\n", evidence)
			}
			fmt.Fprintf(&out, "\n")
		}
		if len(finding.Fixes) > 0 {
			fmt.Fprintf(&out, "Fix suggestions:\n\n")
			fmt.Fprintf(&out, "```text\n")
			for _, fix := range finding.Fixes {
				fmt.Fprintf(&out, "- %s\n", fix)
			}
			fmt.Fprintf(&out, "```\n\n")
		}
	}
	return out.String()
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
