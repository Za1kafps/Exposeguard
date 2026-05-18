package listener

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/model"
	"github.com/Za1kafps/exposeguard/internal/system"
)

type Listener struct {
	Protocol string
	LocalIP  string
	Port     int
	Process  string
	Binding  model.BindingClass
}

type Result struct {
	Listeners []Listener
	Warnings  []model.Warning
}

func Discover(ctx context.Context, runner system.Runner) Result {
	result, err := runner.Run(ctx, "ss", "-tulpen")
	if err != nil {
		return Result{Warnings: []model.Warning{{Source: "listeners", Message: fmt.Sprintf("ss unavailable: %v", err)}}}
	}
	if result.ExitCode != 0 {
		return Result{Warnings: []model.Warning{{Source: "listeners", Message: commandFailure("ss -tulpen", result)}}}
	}
	listeners, warnings := ParseSS(result.Stdout)
	return Result{Listeners: listeners, Warnings: warnings}
}

func ParseSS(output string) ([]Listener, []model.Warning) {
	var listeners []Listener
	var warnings []model.Warning
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			warnings = append(warnings, model.Warning{Source: "listeners", Message: "could not parse ss line: " + line})
			continue
		}
		local := fields[4]
		if fields[0] == "udp" && len(fields) > 4 {
			local = fields[4]
		}
		ip, port, ok := parseAddress(local)
		if !ok {
			warnings = append(warnings, model.Warning{Source: "listeners", Message: "could not parse listener address: " + local})
			continue
		}
		listeners = append(listeners, Listener{
			Protocol: strings.ToLower(fields[0]),
			LocalIP:  ip,
			Port:     port,
			Process:  processName(line),
			Binding:  model.ClassifyBinding(ip),
		})
	}
	return listeners, warnings
}

func parseAddress(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "tcp:")
	value = strings.TrimPrefix(value, "udp:")
	host, portValue, err := net.SplitHostPort(value)
	if err != nil {
		idx := strings.LastIndex(value, ":")
		if idx < 0 {
			return "", 0, false
		}
		host = strings.Trim(value[:idx], "[]")
		portValue = value[idx+1:]
	}
	portValue = strings.Trim(portValue, "*")
	port, err := strconv.Atoi(portValue)
	if err != nil {
		return "", 0, false
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	return strings.Trim(host, "[]"), port, true
}

func processName(line string) string {
	start := strings.Index(line, "users:((")
	if start < 0 {
		return ""
	}
	rest := line[start+8:]
	rest = strings.TrimPrefix(rest, "\"")
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	return rest[:end]
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
