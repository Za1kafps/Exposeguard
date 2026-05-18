package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/model"
	"github.com/Za1kafps/exposeguard/internal/system"
)

type State struct {
	UFWStatus              string
	UFWDefaultIncoming     string
	UFWEvidence            []string
	HasDockerChain         bool
	HasDockerUserChain     bool
	HasDockerNftRules      bool
	DockerFirewallEvidence []string
}

type Result struct {
	State    State
	Warnings []model.Warning
}

func Discover(ctx context.Context, runner system.Runner) Result {
	var warnings []model.Warning
	state := State{UFWStatus: "unknown"}

	ufw, err := runner.Run(ctx, "ufw", "status")
	if err != nil {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: fmt.Sprintf("ufw status unavailable: %v", err)})
	} else if ufw.ExitCode != 0 {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: commandFailure("ufw status", ufw)})
	} else {
		parseUFWStatus(ufw.Stdout, &state)
	}

	verbose, err := runner.Run(ctx, "ufw", "status", "verbose")
	if err != nil {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: fmt.Sprintf("ufw status verbose unavailable: %v", err)})
	} else if verbose.ExitCode != 0 {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: commandFailure("ufw status verbose", verbose)})
	} else {
		parseUFWVerbose(verbose.Stdout, &state)
	}

	iptables, err := runner.Run(ctx, "iptables-save")
	if err != nil {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: fmt.Sprintf("iptables-save unavailable: %v", err)})
	} else if iptables.ExitCode != 0 {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: commandFailure("iptables-save", iptables)})
	} else {
		parseIPTables(iptables.Stdout, &state)
	}

	nft, err := runner.Run(ctx, "nft", "list", "ruleset")
	if err != nil {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: fmt.Sprintf("nft list ruleset unavailable: %v", err)})
	} else if nft.ExitCode != 0 {
		warnings = append(warnings, model.Warning{Source: "firewall", Message: commandFailure("nft list ruleset", nft)})
	} else {
		parseNFT(nft.Stdout, &state)
	}

	return Result{State: state, Warnings: warnings}
}

func parseUFWStatus(output string, state *State) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "status:") {
			status := strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:"))
			if status == "" {
				status = "unknown"
			}
			state.UFWStatus = strings.ToLower(status)
			state.UFWEvidence = appendLimited(state.UFWEvidence, trimmed)
		}
	}
}

func parseUFWVerbose(output string, state *State) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "default:") {
			state.UFWDefaultIncoming = trimmed
			state.UFWEvidence = appendLimited(state.UFWEvidence, trimmed)
		}
		if strings.HasPrefix(lower, "status:") {
			parseUFWStatus(trimmed, state)
		}
	}
}

func parseIPTables(output string, state *State) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ":DOCKER ") || strings.HasPrefix(trimmed, "-N DOCKER") {
			state.HasDockerChain = true
			state.DockerFirewallEvidence = appendLimited(state.DockerFirewallEvidence, trimmed)
		}
		if strings.HasPrefix(trimmed, ":DOCKER-USER ") || strings.HasPrefix(trimmed, "-N DOCKER-USER") {
			state.HasDockerUserChain = true
			state.DockerFirewallEvidence = appendLimited(state.DockerFirewallEvidence, trimmed)
		}
	}
}

func parseNFT(output string, state *State) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "docker") {
			state.HasDockerNftRules = true
			state.DockerFirewallEvidence = appendLimited(state.DockerFirewallEvidence, trimmed)
		}
	}
}

func appendLimited(values []string, value string) []string {
	if value == "" || len(values) >= 8 {
		return values
	}
	return append(values, value)
}

func commandFailure(command string, result system.Result) string {
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
