package rules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/firewall"
	"github.com/Za1kafps/exposeguard/internal/fixes"
	"github.com/Za1kafps/exposeguard/internal/intent"
	"github.com/Za1kafps/exposeguard/internal/listener"
	"github.com/Za1kafps/exposeguard/internal/model"
)

const (
	RulePublicPostgres      = "EG-CRITICAL-001"
	RulePublicMySQL         = "EG-CRITICAL-002"
	RulePublicRedis         = "EG-CRITICAL-003"
	RulePublicMongoDB       = "EG-CRITICAL-004"
	RulePublicDockerDaemon  = "EG-CRITICAL-005"
	RulePublicAdmin         = "EG-HIGH-001"
	RulePublicPortainer     = "EG-HIGH-002"
	RulePublicGrafana       = "EG-HIGH-003"
	RulePublicPrometheus    = "EG-HIGH-004"
	RuleDockerSocketDash    = "EG-HIGH-005"
	RuleReverseProxyBypass  = "EG-HIGH-006"
	RuleUnknownPublic       = "EG-MEDIUM-001"
	RuleHostNetwork         = "EG-MEDIUM-002"
	RuleDirectHTTP          = "EG-MEDIUM-003"
	RuleLocalhostOnly       = "EG-INFO-001"
	RuleNoPublishedPorts    = "EG-INFO-002"
	RuleFirewallUnknown     = "EG-INFO-003"
	RuleDockerUnavailable   = "EG-INFO-004"
	RuleInternalDockerPorts = "EG-INFO-005"
)

type Input struct {
	Docker      []docker.Container
	Compose     *compose.Project
	Firewall    firewall.State
	Listeners   []listener.Listener
	NoDocker    bool
	NoFirewall  bool
	NoListeners bool
	DockerOK    bool
}

func Evaluate(input Input) []model.Finding {
	var chains []model.Finding
	seenPublicPorts := map[string]struct{}{}
	matchedServices := map[string]struct{}{}
	proxies := detectReverseProxies(input)

	for _, container := range input.Docker {
		service := matchComposeService(input.Compose, container)
		if service != nil {
			matchedServices[service.Name] = struct{}{}
		}
		if len(container.PublishedPorts) == 0 && len(container.ExposedPorts) > 0 {
			chains = append(chains, internalExposure(input, container, service))
		}
		for _, port := range container.PublishedPorts {
			if port.Binding == model.BindingPublic {
				seenPublicPorts[fmt.Sprintf("%s/%d", port.Protocol, port.HostPort)] = struct{}{}
				chains = append(chains, publicDockerChain(input, container, service, port, proxies))
				continue
			}
			chains = append(chains, localDockerChain(input, container, service, port))
		}
	}

	if input.Compose != nil {
		for i := range input.Compose.Services {
			service := &input.Compose.Services[i]
			if strings.EqualFold(service.NetworkMode, "host") {
				chains = append(chains, composeHostNetworkChain(input, service))
			}
			if _, matched := matchedServices[service.Name]; matched {
				continue
			}
			for _, spec := range service.Ports {
				hostIP, hostPort, containerPort, protocol, ok := compose.ParsePublishedPort(spec)
				if !ok {
					continue
				}
				port := docker.PublishedPort{
					HostIP:        displayHostIP(hostIP),
					HostPort:      hostPort,
					ContainerPort: containerPort,
					Protocol:      protocol,
					Binding:       model.ClassifyBinding(hostIP),
				}
				if port.Binding == model.BindingPublic {
					chains = append(chains, publicComposeChain(input, service, port, proxies))
				}
			}
		}
	}

	if !input.NoListeners {
		for _, item := range input.Listeners {
			if item.Binding != model.BindingPublic {
				continue
			}
			key := fmt.Sprintf("%s/%d", item.Protocol, item.Port)
			if _, ok := seenPublicPorts[key]; ok {
				continue
			}
			if finding, ok := publicListenerChain(input, item); ok {
				chains = append(chains, finding)
			}
		}
	}

	if !input.NoFirewall && input.Firewall.UFWStatus == "unknown" {
		chains = append(chains, firewallUnknownChain(input))
	}
	if !input.NoDocker && !input.DockerOK {
		chains = append(chains, dockerUnavailableChain())
	}
	if !input.NoDocker && input.DockerOK && !hasPublishedDockerPorts(input.Docker) {
		chains = append(chains, noPublishedPortsChain())
	}

	sortFindings(chains)
	assignStableIDs(chains)
	return chains
}

func hasPublishedDockerPorts(containers []docker.Container) bool {
	for _, container := range containers {
		if len(container.PublishedPorts) > 0 {
			return true
		}
	}
	return false
}

func publicDockerChain(input Input, container docker.Container, service *compose.Service, port docker.PublishedPort, proxies []model.ReverseProxyEvidence) model.Finding {
	svcIntent := intent.Infer(intent.Input{Compose: service, Container: &container, HostPort: port.HostPort, ContainerPort: port.ContainerPort})
	proxy := reverseProxyFor(service, container, proxies)
	rule := selectPublicRule(container, service, port, svcIntent, proxy != nil)
	chain := baseContainerChain(input, container, service, port, svcIntent)
	chain.RuleID = rule.id
	chain.Title = rule.title
	chain.Severity = rule.severity
	chain.Reason = rule.reason
	chain.Impact = rule.impact
	chain.ReverseProxy = proxy
	chain.Evidence = append(chain.Evidence, model.Evidence{
		Source:     "rule",
		Summary:    rule.evidence,
		Confidence: rule.confidence,
	})
	if proxy != nil {
		chain.Evidence = append(chain.Evidence, proxy.Evidence...)
	}
	chain.Fixes = fixes.Generate(fixes.Input{
		Intent:        svcIntent,
		RuleID:        chain.RuleID,
		ServiceName:   chain.ServiceName,
		HostPort:      port.HostPort,
		ContainerPort: port.ContainerPort,
		Protocol:      port.Protocol,
		HasCompose:    service != nil,
		BehindProxy:   chain.RuleID == RuleReverseProxyBypass,
	})
	return chain
}

func baseContainerChain(input Input, container docker.Container, service *compose.Service, port docker.PublishedPort, svcIntent model.ServiceIntent) model.Finding {
	chain := model.Finding{
		ServiceName:   serviceName(service, container),
		ContainerName: container.Name,
		Image:         container.Image,
		Port:          port.HostPort,
		Protocol:      port.Protocol,
		Binding:       model.BindingDescription(port.HostIP, port.HostPort),
		Container:     containerEvidence(container),
		PublishedPort: &model.PublishedPortEvidence{HostIP: port.HostIP, HostPort: port.HostPort, ContainerPort: port.ContainerPort, Protocol: port.Protocol, Binding: port.Binding},
		Intent:        svcIntent,
	}
	if service != nil {
		chain.Compose = composeEvidence(input.Compose, service)
	}
	chain.Evidence = append(chain.Evidence, model.Evidence{
		Source:  "docker",
		Summary: fmt.Sprintf("container %s publishes %s:%d->%d/%s", container.Name, displayHostIP(port.HostIP), port.HostPort, port.ContainerPort, port.Protocol),
		Details: map[string]string{
			"container":      container.Name,
			"image":          container.Image,
			"host_ip":        displayHostIP(port.HostIP),
			"host_port":      strconv.Itoa(port.HostPort),
			"container_port": strconv.Itoa(port.ContainerPort),
			"protocol":       port.Protocol,
		},
		Confidence: "high",
	})
	if chain.Compose != nil {
		chain.Evidence = append(chain.Evidence, model.Evidence{
			Source:     "compose",
			Summary:    "compose service context is available for this container",
			Details:    composeDetails(chain.Compose),
			Confidence: "medium",
		})
	}
	chain.Firewall = firewallEvidence(input.Firewall)
	chain.Evidence = append(chain.Evidence, chain.Firewall...)
	chain.Listener = matchingListenerEvidence(input.Listeners, port)
	chain.Evidence = append(chain.Evidence, chain.Listener...)
	if len(svcIntent.Signals) > 0 {
		chain.Evidence = append(chain.Evidence, model.Evidence{
			Source:     "inference",
			Summary:    "service intent inferred as " + svcIntent.Category,
			Details:    map[string]string{"confidence": svcIntent.Confidence, "signals": strings.Join(svcIntent.Signals, "; ")},
			Confidence: svcIntent.Confidence,
		})
	}
	return chain
}

func publicComposeChain(input Input, service *compose.Service, port docker.PublishedPort, proxies []model.ReverseProxyEvidence) model.Finding {
	svcIntent := intent.Infer(intent.Input{Compose: service, HostPort: port.HostPort, ContainerPort: port.ContainerPort})
	proxy := reverseProxyFor(service, docker.Container{}, proxies)
	rule := selectPublicRule(docker.Container{Name: service.Name, Image: service.Image}, service, port, svcIntent, proxy != nil)
	chain := model.Finding{
		RuleID:        rule.id,
		Title:         rule.title,
		Severity:      rule.severity,
		ServiceName:   service.Name,
		Image:         service.Image,
		Port:          port.HostPort,
		Protocol:      port.Protocol,
		Binding:       model.BindingDescription(port.HostIP, port.HostPort),
		Compose:       composeEvidence(input.Compose, service),
		PublishedPort: &model.PublishedPortEvidence{HostIP: port.HostIP, HostPort: port.HostPort, ContainerPort: port.ContainerPort, Protocol: port.Protocol, Binding: port.Binding},
		Intent:        svcIntent,
		ReverseProxy:  proxy,
		Reason:        rule.reason,
		Impact:        rule.impact,
		Evidence: []model.Evidence{
			{
				Source:     "compose",
				Summary:    fmt.Sprintf("compose service %s publishes %s:%d->%d/%s", service.Name, displayHostIP(port.HostIP), port.HostPort, port.ContainerPort, port.Protocol),
				Details:    map[string]string{"service": service.Name, "host_port": strconv.Itoa(port.HostPort), "container_port": strconv.Itoa(port.ContainerPort), "protocol": port.Protocol},
				Confidence: "medium",
			},
			{Source: "rule", Summary: rule.evidence, Confidence: rule.confidence},
		},
	}
	chain.Firewall = firewallEvidence(input.Firewall)
	chain.Evidence = append(chain.Evidence, chain.Firewall...)
	if proxy != nil {
		chain.Evidence = append(chain.Evidence, proxy.Evidence...)
	}
	chain.Fixes = fixes.Generate(fixes.Input{
		Intent:        svcIntent,
		RuleID:        chain.RuleID,
		ServiceName:   chain.ServiceName,
		HostPort:      port.HostPort,
		ContainerPort: port.ContainerPort,
		Protocol:      port.Protocol,
		HasCompose:    true,
		BehindProxy:   chain.RuleID == RuleReverseProxyBypass,
	})
	return chain
}

func localDockerChain(input Input, container docker.Container, service *compose.Service, port docker.PublishedPort) model.Finding {
	svcIntent := intent.Infer(intent.Input{Compose: service, Container: &container, HostPort: port.HostPort, ContainerPort: port.ContainerPort})
	chain := baseContainerChain(input, container, service, port, svcIntent)
	chain.RuleID = RuleLocalhostOnly
	chain.Title = "Docker service is bound to localhost"
	chain.Severity = model.SeverityInfo
	chain.Reason = "The published port is bound to a loopback address."
	chain.Impact = "The service should only be reachable from the host or a local reverse proxy."
	chain.Fixes = []model.Fix{{Title: "Keep localhost binding", Summary: "No change is needed if localhost-only access is intentional.", Safe: true}}
	return chain
}

func internalExposure(input Input, container docker.Container, service *compose.Service) model.Finding {
	var exposed []string
	for _, port := range container.ExposedPorts {
		exposed = append(exposed, fmt.Sprintf("%d/%s", port.Port, port.Protocol))
	}
	svcIntent := intent.Infer(intent.Input{Compose: service, Container: &container})
	chain := model.Finding{
		RuleID:        RuleInternalDockerPorts,
		Title:         "Docker service exposes internal ports only",
		Severity:      model.SeverityInfo,
		ServiceName:   serviceName(service, container),
		ContainerName: container.Name,
		Image:         container.Image,
		Container:     containerEvidence(container),
		Intent:        svcIntent,
		Reason:        "The container declares exposed ports but Docker did not publish them to the host.",
		Impact:        "The service is not exposed through Docker port publishing.",
		Evidence:      []model.Evidence{{Source: "docker", Summary: "exposed ports: " + strings.Join(exposed, ", "), Confidence: "high"}},
		Fixes:         []model.Fix{{Title: "Keep service internal", Summary: "No change is needed if the service is meant to stay internal.", Safe: true}},
	}
	if service != nil {
		chain.Compose = composeEvidence(input.Compose, service)
	}
	return chain
}

func composeHostNetworkChain(input Input, service *compose.Service) model.Finding {
	svcIntent := intent.Infer(intent.Input{Compose: service})
	return model.Finding{
		RuleID:      RuleHostNetwork,
		Title:       "Compose service uses host networking",
		Severity:    model.SeverityMedium,
		ServiceName: service.Name,
		Image:       service.Image,
		Compose:     composeEvidence(input.Compose, service),
		Intent:      svcIntent,
		Reason:      "network_mode: host places the service directly on the host network namespace.",
		Impact:      "Ports opened by the process can become host listeners without Docker published port metadata.",
		Evidence: []model.Evidence{{
			Source:     "compose",
			Summary:    "compose service " + service.Name + " sets network_mode: host",
			Confidence: "high",
		}},
		Fixes: []model.Fix{
			{Title: "Use bridge networking", Summary: "Use bridge networking and publish only the ports that must be reachable.", Safe: true},
			{Title: "Confirm host listeners", Summary: "Run with listener checks enabled to confirm host-level listeners.", Safe: true},
		},
	}
}

func publicListenerChain(input Input, item listener.Listener) (model.Finding, bool) {
	svcIntent := intent.Infer(intent.Input{HostPort: item.Port, ContainerPort: item.Port})
	svc := serviceForPort(item.Process, item.Process, item.Port, item.Port)
	if !svc.critical && !svc.high {
		return model.Finding{}, false
	}
	severity := model.SeverityHigh
	ruleID := RulePublicAdmin
	if svc.critical {
		severity = model.SeverityCritical
		ruleID = svc.ruleID
	}
	return model.Finding{
		RuleID:      ruleID,
		Title:       svc.display + " listener is public",
		Severity:    severity,
		ServiceName: svc.name,
		Port:        item.Port,
		Protocol:    item.Protocol,
		Binding:     model.BindingDescription(item.LocalIP, item.Port),
		Intent:      svcIntent,
		Reason:      fmt.Sprintf("A host listener is bound to a public interface on port %d.", item.Port),
		Impact:      "The process may be reachable from networks that can route to this host.",
		Listener:    []model.Evidence{listenerEvidence(item)},
		Evidence:    []model.Evidence{listenerEvidence(item)},
		Fixes:       []model.Fix{{Title: "Restrict listener access", Summary: "Bind the service to 127.0.0.1 or restrict access with host firewall policy.", Safe: true}},
	}, true
}

func firewallUnknownChain(input Input) model.Finding {
	return model.Finding{
		RuleID:   RuleFirewallUnknown,
		Title:    "Firewall state is unknown",
		Severity: model.SeverityInfo,
		Intent:   model.ServiceIntent{Category: "unknown", Confidence: "low"},
		Reason:   "ExposeGuard could not determine host firewall state from available commands.",
		Impact:   "Exposure decisions may need manual confirmation against your firewall backend.",
		Firewall: firewallEvidence(input.Firewall),
		Evidence: []model.Evidence{{Source: "firewall", Summary: "firewall state could not be determined", Confidence: "low"}},
		Fixes:    []model.Fix{{Title: "Read firewall state", Summary: "Run with sufficient permissions to read ufw, iptables-save and nft list ruleset output.", Safe: true}},
	}
}

func dockerUnavailableChain() model.Finding {
	return model.Finding{
		RuleID:   RuleDockerUnavailable,
		Title:    "Docker discovery is unavailable",
		Severity: model.SeverityInfo,
		Intent:   model.ServiceIntent{Category: "unknown", Confidence: "low"},
		Reason:   "ExposeGuard could not complete Docker discovery on this host.",
		Impact:   "Docker-published services may be missing from this scan.",
		Fixes:    []model.Fix{{Title: "Run with Docker access", Summary: "Run on a host with Docker CLI access, or use --no-docker when Docker is intentionally out of scope.", Safe: true}},
	}
}

func noPublishedPortsChain() model.Finding {
	return model.Finding{
		RuleID:   RuleNoPublishedPorts,
		Title:    "No Docker published ports were found",
		Severity: model.SeverityInfo,
		Intent:   model.ServiceIntent{Category: "unknown", Confidence: "low"},
		Reason:   "Docker discovery completed and did not find host-published container ports.",
		Impact:   "ExposeGuard did not identify public Docker bindings from Docker metadata.",
		Evidence: []model.Evidence{{Source: "docker", Summary: "docker ps and docker inspect completed without published port mappings", Confidence: "high"}},
		Fixes:    []model.Fix{{Title: "No Docker port change needed", Summary: "No change is needed if services are intentionally internal or not running.", Safe: true}},
	}
}

type publicRule struct {
	id         string
	title      string
	severity   model.Severity
	reason     string
	impact     string
	evidence   string
	confidence string
}

func selectPublicRule(container docker.Container, service *compose.Service, port docker.PublishedPort, svcIntent model.ServiceIntent, behindProxy bool) publicRule {
	svc := serviceForPort(container.Name, container.Image, port.HostPort, port.ContainerPort)
	if behindProxy && intent.IsInternalLike(svcIntent) {
		return publicRule{
			id:         RuleReverseProxyBypass,
			title:      "Backend is reachable directly, bypassing the reverse proxy",
			severity:   model.SeverityHigh,
			reason:     fmt.Sprintf("The service appears connected to a reverse proxy context, but also publishes %s:%d directly.", displayHostIP(port.HostIP), port.HostPort),
			impact:     "Requests can bypass TLS, authentication, rate limiting, IP filtering, headers and routing rules enforced at the proxy.",
			evidence:   "public backend port exists while reverse proxy context is present",
			confidence: "medium",
		}
	}
	if docker.HasDockerSocket(container) && (svcIntent.Category == "dashboard" || looksDashboard(container.Name, container.Image, port.HostPort)) {
		return publicRule{RuleDockerSocketDash, "Public dashboard has the Docker socket mounted", model.SeverityHigh, "The service is public and can access /var/run/docker.sock from the container.", "A compromise of the dashboard can become host-level container control.", "docker socket mount detected on public dashboard", "high"}
	}
	if svc.critical {
		return publicRule{svc.ruleID, svc.display + " is publicly exposed", model.SeverityCritical, fmt.Sprintf("%s is bound to a public interface on port %d.", svc.display, port.HostPort), "This service is commonly targeted and should not be reachable directly from the internet without a deliberate access control layer.", "known dangerous service exposed publicly", "high"}
	}
	if svc.high {
		return publicRule{svc.ruleID, svc.display + " is publicly exposed", model.SeverityHigh, fmt.Sprintf("%s is reachable on a public binding.", svc.display), "Administrative and observability interfaces often expose sensitive operations or internal data.", "known administrative or observability service exposed publicly", "high"}
	}
	if hasAdminKeyword(container.Name, container.Image, service) {
		return publicRule{RulePublicAdmin, "Public service name looks administrative", model.SeverityHigh, "The service name, image or Compose metadata includes dashboard, admin, panel or manager keywords and is published publicly.", "An administrative interface may be reachable without the reverse proxy or access policy you expected.", "administrative keyword on public service", "medium"}
	}
	if isDirectHTTP(port.HostPort, container.Name, container.Image, labelsOf(service, container)) && svcIntent.Category != "reverse-proxy" {
		return publicRule{RuleDirectHTTP, "HTTP service is exposed directly", model.SeverityMedium, "HTTP or HTTPS is published publicly without a known reverse proxy context in the service metadata.", "The service may be reachable directly instead of through the expected TLS, authentication and routing layer.", "direct public HTTP binding without proxy evidence", "medium"}
	}
	reason := "A Docker published port is bound to a public interface."
	if svcIntent.Category != "unknown" {
		reason = fmt.Sprintf("A service inferred as %s is published on a public interface.", svcIntent.Category)
	}
	return publicRule{RuleUnknownPublic, "Unknown public Docker service", model.SeverityMedium, reason, "The service may be reachable from the internet depending on host networking and firewall policy.", "public Docker binding with uncertain service intent", "medium"}
}

type serviceMatch struct {
	name     string
	display  string
	ruleID   string
	critical bool
	high     bool
}

func serviceForPort(name, image string, hostPort, containerPort int) serviceMatch {
	text := strings.ToLower(name + " " + image)
	port := hostPort
	if containerPort > 0 {
		port = containerPort
	}
	matches := []struct {
		name     string
		display  string
		ruleID   string
		port     int
		keywords []string
		critical bool
	}{
		{"postgresql", "PostgreSQL", RulePublicPostgres, 5432, []string{"postgres", "postgresql"}, true},
		{"mysql", "MySQL or MariaDB", RulePublicMySQL, 3306, []string{"mysql", "mariadb"}, true},
		{"redis", "Redis", RulePublicRedis, 6379, []string{"redis"}, true},
		{"mongodb", "MongoDB", RulePublicMongoDB, 27017, []string{"mongo", "mongodb"}, true},
		{"docker-daemon", "Docker daemon", RulePublicDockerDaemon, 2375, []string{"docker"}, true},
		{"docker-daemon", "Docker daemon", RulePublicDockerDaemon, 2376, []string{"docker"}, true},
		{"portainer", "Portainer", RulePublicPortainer, 9000, []string{"portainer"}, false},
		{"portainer", "Portainer", RulePublicPortainer, 9443, []string{"portainer"}, false},
		{"grafana", "Grafana", RulePublicGrafana, 3000, []string{"grafana"}, false},
		{"prometheus", "Prometheus", RulePublicPrometheus, 9090, []string{"prometheus"}, false},
		{"elasticsearch", "Elasticsearch", RulePublicAdmin, 9200, []string{"elastic", "elasticsearch"}, false},
		{"rabbitmq-management", "RabbitMQ management", RulePublicAdmin, 15672, []string{"rabbitmq"}, false},
	}
	for _, match := range matches {
		if port == match.port || hasAny(text, match.keywords) && (hostPort == match.port || containerPort == match.port || hostPort == 0 && containerPort == 0) {
			return serviceMatch{name: match.name, display: match.display, ruleID: match.ruleID, critical: match.critical, high: !match.critical}
		}
	}
	return serviceMatch{name: "unknown", display: "Unknown service"}
}

func detectReverseProxies(input Input) []model.ReverseProxyEvidence {
	var proxies []model.ReverseProxyEvidence
	if input.Compose != nil {
		for i := range input.Compose.Services {
			service := &input.Compose.Services[i]
			svcIntent := intent.Infer(intent.Input{Compose: service})
			if svcIntent.Category != "reverse-proxy" {
				continue
			}
			proxies = append(proxies, model.ReverseProxyEvidence{
				Present:        true,
				ServiceName:    service.Name,
				Image:          service.Image,
				Networks:       service.Networks,
				PublishedPorts: composeHostPorts(service.Ports),
				Evidence:       []model.Evidence{{Source: "inference", Summary: "reverse proxy service inferred from Compose metadata", Details: map[string]string{"service": service.Name, "signals": strings.Join(svcIntent.Signals, "; ")}, Confidence: svcIntent.Confidence}},
			})
		}
	}
	for _, container := range input.Docker {
		svcIntent := intent.Infer(intent.Input{Container: &container})
		if svcIntent.Category != "reverse-proxy" {
			continue
		}
		proxies = append(proxies, model.ReverseProxyEvidence{
			Present:        true,
			ContainerName:  container.Name,
			Image:          container.Image,
			Networks:       container.Networks,
			PublishedPorts: dockerHostPorts(container.PublishedPorts),
			Evidence:       []model.Evidence{{Source: "inference", Summary: "reverse proxy container inferred from Docker metadata", Details: map[string]string{"container": container.Name, "signals": strings.Join(svcIntent.Signals, "; ")}, Confidence: svcIntent.Confidence}},
		})
	}
	return proxies
}

func reverseProxyFor(service *compose.Service, container docker.Container, proxies []model.ReverseProxyEvidence) *model.ReverseProxyEvidence {
	for _, proxy := range proxies {
		if service != nil && service.Name == proxy.ServiceName {
			continue
		}
		if container.Name != "" && container.Name == proxy.ContainerName {
			continue
		}
		if service != nil && sharesNetwork(service.Networks, proxy.Networks) {
			copy := proxy
			return &copy
		}
		if sharesNetwork(container.Networks, proxy.Networks) {
			copy := proxy
			return &copy
		}
		if service != nil && hasReverseProxyLabels(service.Labels) {
			copy := proxy
			return &copy
		}
	}
	return nil
}

func matchComposeService(project *compose.Project, container docker.Container) *compose.Service {
	if project == nil {
		return nil
	}
	if serviceName := container.Labels["com.docker.compose.service"]; serviceName != "" {
		for i := range project.Services {
			if project.Services[i].Name == serviceName {
				return &project.Services[i]
			}
		}
	}
	normalizedContainer := normalizeName(container.Name)
	for i := range project.Services {
		service := &project.Services[i]
		if normalizeName(service.Name) == normalizedContainer || strings.Contains(normalizedContainer, normalizeName(service.Name)) {
			return service
		}
		if service.Image != "" && service.Image == container.Image {
			return service
		}
	}
	return nil
}

func composeEvidence(project *compose.Project, service *compose.Service) *model.ComposeEvidence {
	if service == nil {
		return nil
	}
	file := ""
	if project != nil {
		file = project.Path
	}
	return &model.ComposeEvidence{
		File:            file,
		ServiceName:     service.Name,
		Image:           service.Image,
		Ports:           append([]string(nil), service.Ports...),
		Expose:          append([]string(nil), service.Expose...),
		Networks:        append([]string(nil), service.Networks...),
		NetworkMode:     service.NetworkMode,
		Privileged:      service.Privileged,
		Volumes:         append([]string(nil), service.Volumes...),
		EnvironmentKeys: append([]string(nil), service.EnvironmentKeys...),
		Labels:          safeLabels(service.Labels),
		Command:         redactedPresence(service.Command),
		Healthcheck:     redactedPresence(service.Healthcheck),
	}
}

func containerEvidence(container docker.Container) *model.ContainerEvidence {
	return &model.ContainerEvidence{
		ID:       container.ID,
		Name:     container.Name,
		Image:    container.Image,
		State:    container.State,
		Labels:   safeLabels(container.Labels),
		Networks: append([]string(nil), container.Networks...),
		Mounts:   mountSummaries(container),
	}
}

func firewallEvidence(state firewall.State) []model.Evidence {
	var evidence []model.Evidence
	if state.UFWStatus != "" {
		details := map[string]string{"ufw_status": state.UFWStatus}
		if state.UFWDefaultIncoming != "" {
			details["ufw_default_incoming"] = state.UFWDefaultIncoming
		}
		evidence = append(evidence, model.Evidence{Source: "firewall", Summary: "ufw status: " + state.UFWStatus, Details: details, Confidence: confidenceForKnown(state.UFWStatus)})
	}
	if state.HasDockerChain {
		evidence = append(evidence, model.Evidence{Source: "firewall", Summary: "iptables DOCKER chain detected", Confidence: "high"})
	}
	if state.HasDockerUserChain {
		evidence = append(evidence, model.Evidence{Source: "firewall", Summary: "iptables DOCKER-USER chain detected", Confidence: "high"})
	}
	if state.HasDockerNftRules {
		evidence = append(evidence, model.Evidence{Source: "firewall", Summary: "docker-related nftables rules detected", Confidence: "medium"})
	}
	for _, item := range state.DockerFirewallEvidence {
		evidence = append(evidence, model.Evidence{Source: "firewall", Summary: "firewall evidence: " + item, Confidence: "medium"})
	}
	return evidence
}

func matchingListenerEvidence(listeners []listener.Listener, port docker.PublishedPort) []model.Evidence {
	var evidence []model.Evidence
	for _, item := range listeners {
		if item.Port == port.HostPort && strings.EqualFold(item.Protocol, port.Protocol) {
			evidence = append(evidence, listenerEvidence(item))
		}
	}
	return evidence
}

func listenerEvidence(item listener.Listener) model.Evidence {
	details := map[string]string{
		"protocol": item.Protocol,
		"ip":       item.LocalIP,
		"port":     strconv.Itoa(item.Port),
	}
	if item.Process != "" {
		details["process"] = item.Process
	}
	return model.Evidence{Source: "listener", Summary: fmt.Sprintf("ss reports %s listener on %s:%d", item.Protocol, displayHostIP(item.LocalIP), item.Port), Details: details, Confidence: "medium"}
}

func assignStableIDs(findings []model.Finding) {
	counts := map[string]int{}
	for i := range findings {
		if findings[i].ID != "" {
			continue
		}
		base := findings[i].RuleID
		if base == "" {
			base = "EG-UNKNOWN"
		}
		counts[base]++
		if counts[base] == 1 {
			findings[i].ID = base
			continue
		}
		findings[i].ID = fmt.Sprintf("%s-%02d", base, counts[base])
	}
}

func sortFindings(findings []model.Finding) {
	rank := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if rank[findings[i].Severity] != rank[findings[j].Severity] {
			return rank[findings[i].Severity] < rank[findings[j].Severity]
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Title < findings[j].Title
	})
}

func serviceName(service *compose.Service, container docker.Container) string {
	if service != nil && service.Name != "" {
		return service.Name
	}
	if name := container.Labels["com.docker.compose.service"]; name != "" {
		return name
	}
	return serviceForPort(container.Name, container.Image, 0, 0).name
}

func composeDetails(evidence *model.ComposeEvidence) map[string]string {
	details := map[string]string{"service": evidence.ServiceName}
	if evidence.File != "" {
		details["file"] = evidence.File
	}
	if len(evidence.Ports) > 0 {
		details["ports"] = strings.Join(evidence.Ports, ", ")
	}
	if len(evidence.Expose) > 0 {
		details["expose"] = strings.Join(evidence.Expose, ", ")
	}
	if len(evidence.EnvironmentKeys) > 0 {
		details["environment_keys"] = strings.Join(evidence.EnvironmentKeys, ", ")
	}
	return details
}

func mountSummaries(container docker.Container) []string {
	var values []string
	for _, mount := range container.Mounts {
		if mount.Destination != "" {
			values = append(values, mount.Destination)
		}
	}
	for _, bind := range container.Binds {
		_, destination, ok := strings.Cut(bind, ":")
		if ok && destination != "" {
			values = append(values, destination)
		}
	}
	sort.Strings(values)
	return values
}

func safeLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	safe := map[string]string{}
	for key, value := range labels {
		if looksSensitiveKey(key) || looksSensitiveKey(value) {
			safe[key] = "<redacted>"
			continue
		}
		safe[key] = value
	}
	return safe
}

func looksSensitiveKey(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "password") || strings.Contains(lower, "passwd") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "key")
}

func redactedPresence(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "configured"
}

func labelsOf(service *compose.Service, container docker.Container) map[string]string {
	labels := map[string]string{}
	for key, value := range container.Labels {
		labels[key] = value
	}
	if service != nil {
		for key, value := range service.Labels {
			labels[key] = value
		}
	}
	return labels
}

func hasReverseProxyLabels(labels map[string]string) bool {
	for key := range labels {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "traefik.") || strings.HasPrefix(lower, "caddy.") || strings.HasPrefix(lower, "nginx.") || strings.HasPrefix(lower, "nginx-proxy.") {
			return true
		}
	}
	return false
}

func composeHostPorts(ports []string) []int {
	var values []int
	for _, spec := range ports {
		_, hostPort, _, _, ok := compose.ParsePublishedPort(spec)
		if ok && hostPort > 0 {
			values = append(values, hostPort)
		}
	}
	sort.Ints(values)
	return values
}

func dockerHostPorts(ports []docker.PublishedPort) []int {
	var values []int
	for _, port := range ports {
		values = append(values, port.HostPort)
	}
	sort.Ints(values)
	return values
}

func sharesNetwork(left, right []string) bool {
	set := map[string]struct{}{}
	for _, item := range left {
		set[item] = struct{}{}
	}
	for _, item := range right {
		if _, ok := set[item]; ok && item != "" {
			return true
		}
	}
	return false
}

func hasAdminKeyword(name, image string, service *compose.Service) bool {
	text := strings.ToLower(name + " " + image)
	if service != nil {
		text += " " + strings.ToLower(service.Name+" "+service.Image)
	}
	return hasAny(text, []string{"dashboard", "admin", "panel", "manager"})
}

func looksDashboard(name, image string, port int) bool {
	return hasAny(strings.ToLower(name+" "+image), []string{"dashboard", "admin", "panel", "manager", "grafana", "portainer"}) || port == 3000 || port == 9000 || port == 9443
}

func isDirectHTTP(port int, name, image string, labels map[string]string) bool {
	if port != 80 && port != 443 && port != 8080 && port != 8443 {
		return false
	}
	text := strings.ToLower(name + " " + image)
	if hasAny(text, []string{"nginx", "caddy", "traefik", "haproxy", "envoy", "apache"}) {
		return false
	}
	return !hasReverseProxyLabels(labels)
}

func hasAny(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

func normalizeName(value string) string {
	value = strings.TrimPrefix(value, "/")
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, "_", "")
	return value
}

func displayHostIP(hostIP string) string {
	if strings.TrimSpace(hostIP) == "" {
		return "0.0.0.0"
	}
	return hostIP
}

func confidenceForKnown(value string) string {
	if value == "" || value == "unknown" {
		return "low"
	}
	return "medium"
}
