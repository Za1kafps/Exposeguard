package fixes

import (
	"fmt"

	"github.com/Za1kafps/exposeguard/internal/model"
)

type Input struct {
	Intent        model.ServiceIntent
	RuleID        string
	ServiceName   string
	HostPort      int
	ContainerPort int
	Protocol      string
	HasCompose    bool
	BehindProxy   bool
}

func Generate(input Input) []model.Fix {
	if input.RuleID == "EG-HIGH-006" || input.BehindProxy {
		return reverseProxyBypassFixes(input)
	}
	switch input.Intent.Category {
	case "database", "cache", "queue", "object-storage", "search":
		return internalServiceFixes(input)
	case "dashboard", "metrics":
		return dashboardFixes(input)
	case "public-web":
		return publicWebFixes(input)
	case "internal-api":
		return internalAPIFixes(input)
	default:
		return unknownFixes(input)
	}
}

func internalServiceFixes(input Input) []model.Fix {
	return []model.Fix{
		{
			Title:            "Remove the public port",
			Summary:          "Keep dependent containers on the same Docker network and avoid publishing this service to the host.",
			ComposePatchHint: composeRemovePorts(input),
			Safe:             true,
		},
		{
			Title:            "Bind to localhost when host access is required",
			Summary:          "Use a loopback-only binding so the service is reachable from the host but not directly from external networks.",
			ComposePatchHint: composeLocalhostPort(input),
			Safe:             true,
		},
		{
			Title:    "Use a private access layer for remote administration",
			Summary:  "If remote access is truly required, put it behind a VPN or a strict source-IP firewall policy.",
			Warnings: []string{"Do not expose databases, caches, queues or storage engines directly to the internet."},
			Safe:     true,
		},
	}
}

func dashboardFixes(input Input) []model.Fix {
	return []model.Fix{
		{
			Title:            "Put the dashboard behind a protected reverse proxy",
			Summary:          "Publish only the proxy on 80/443 and enforce TLS, authentication and access policy there.",
			ComposePatchHint: composeExposeOnly(input),
			Safe:             true,
		},
		{
			Title:            "Bind dashboard access to localhost",
			Summary:          "Use loopback binding when the dashboard is reached through an SSH tunnel or local proxy.",
			ComposePatchHint: composeLocalhostPort(input),
			Safe:             true,
		},
	}
}

func internalAPIFixes(input Input) []model.Fix {
	return []model.Fix{
		{
			Title:            "Use internal Docker networking",
			Summary:          "Remove the public port and let the reverse proxy or frontend reach the service by Docker service name.",
			ComposePatchHint: composeExposeOnly(input),
			Safe:             true,
		},
		{
			Title:    "Publish only the intended edge service",
			Summary:  "Keep public 80/443 on the reverse proxy and avoid host-published backend ports.",
			Warnings: []string{"Do not rely on application-level auth alone if a proxy is expected to enforce policy."},
			Safe:     true,
		},
	}
}

func reverseProxyBypassFixes(input Input) []model.Fix {
	return []model.Fix{
		{
			Title:            "Remove backend ports",
			Summary:          "Remove the backend service ports entry so requests must pass through the reverse proxy.",
			ComposePatchHint: composeExposeOnly(input),
			Safe:             true,
		},
		{
			Title:   "Keep the backend and proxy on the same internal network",
			Summary: "Use expose for the backend container port and attach both services to the shared Docker network.",
			Safe:    true,
		},
		{
			Title:   "Publish only the reverse proxy",
			Summary: "Keep public host ports on the proxy service, normally 80 and 443.",
			Safe:    true,
		},
	}
}

func publicWebFixes(input Input) []model.Fix {
	return []model.Fix{
		{
			Title:   "Confirm this is the intended edge service",
			Summary: "Direct public 80/443 can be acceptable for the service that intentionally terminates public HTTP traffic.",
			Safe:    true,
		},
		{
			Title:            "Move non-edge HTTP services behind the proxy",
			Summary:          "If this is not the edge service, remove the public port and use expose on an internal Docker network.",
			ComposePatchHint: composeExposeOnly(input),
			Safe:             true,
		},
	}
}

func unknownFixes(input Input) []model.Fix {
	return []model.Fix{
		{
			Title:            "Make the binding local-only",
			Summary:          "Bind the service to 127.0.0.1 until you confirm it is meant to be public.",
			ComposePatchHint: composeLocalhostPort(input),
			Safe:             true,
		},
		{
			Title:            "Remove the published port if the service is internal",
			Summary:          "Use expose and a shared Docker network for container-to-container traffic.",
			ComposePatchHint: composeExposeOnly(input),
			Safe:             true,
		},
	}
}

func composeRemovePorts(input Input) string {
	if !input.HasCompose {
		return ""
	}
	return "Remove the service ports entry and keep traffic on a private Docker network."
}

func composeLocalhostPort(input Input) string {
	if !input.HasCompose || input.HostPort == 0 || input.ContainerPort == 0 {
		return ""
	}
	return fmt.Sprintf("ports:\n  - \"127.0.0.1:%d:%d/%s\"", input.HostPort, input.ContainerPort, defaultProtocol(input.Protocol))
}

func composeExposeOnly(input Input) string {
	if !input.HasCompose || input.ContainerPort == 0 {
		return ""
	}
	return fmt.Sprintf("expose:\n  - \"%d\"", input.ContainerPort)
}

func defaultProtocol(protocol string) string {
	if protocol == "" {
		return "tcp"
	}
	return protocol
}
