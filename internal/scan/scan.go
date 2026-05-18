package scan

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/firewall"
	"github.com/Za1kafps/exposeguard/internal/listener"
	"github.com/Za1kafps/exposeguard/internal/model"
	"github.com/Za1kafps/exposeguard/internal/rules"
	"github.com/Za1kafps/exposeguard/internal/system"
)

const Version = "0.1.0"

type Options struct {
	ComposeFile string
	NoDocker    bool
	NoFirewall  bool
	NoListeners bool
	Verbose     bool
}

func Run(ctx context.Context, runner system.Runner, options Options) (model.Report, error) {
	var warnings []model.Warning

	var dockerResult docker.Result
	if !options.NoDocker {
		dockerResult = docker.Discover(ctx, runner)
		warnings = append(warnings, dockerResult.Warnings...)
	}

	var composeProject *compose.Project
	if options.ComposeFile != "" {
		project, err := compose.ParseFile(options.ComposeFile)
		if err != nil {
			return model.Report{}, err
		}
		composeProject = &project
	}

	var firewallResult firewall.Result
	if !options.NoFirewall {
		firewallResult = firewall.Discover(ctx, runner)
		warnings = append(warnings, firewallResult.Warnings...)
	}

	var listenerResult listener.Result
	if !options.NoListeners {
		listenerResult = listener.Discover(ctx, runner)
		warnings = append(warnings, listenerResult.Warnings...)
	}

	findings := rules.Evaluate(rules.Input{
		Docker:      dockerResult.Containers,
		Compose:     composeProject,
		Firewall:    firewallResult.State,
		Listeners:   listenerResult.Listeners,
		NoDocker:    options.NoDocker,
		NoFirewall:  options.NoFirewall,
		NoListeners: options.NoListeners,
		DockerOK:    options.NoDocker || dockerResult.Available,
	})

	hostname, _ := os.Hostname()
	report := model.Report{
		Metadata: model.Metadata{
			Tool:        "exposeguard",
			Version:     Version,
			GeneratedAt: time.Now(),
			Hostname:    hostname,
		},
		Findings: findings,
		Warnings: warnings,
	}
	report.Summary = model.BuildSummary(findings)
	return report, nil
}

func WriteOutput(path string, data []byte) error {
	if path == "" {
		return nil
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
