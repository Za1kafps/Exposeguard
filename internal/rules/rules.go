package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/firewall"
	"github.com/Za1kafps/exposeguard/internal/listener"
	"github.com/Za1kafps/exposeguard/internal/model"
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
	var findings []model.Finding
	seenPublicPorts := map[string]struct{}{}

	for _, container := range input.Docker {
		if len(container.PublishedPorts) == 0 && len(container.ExposedPorts) > 0 {
			findings = append(findings, internalExposure(container))
		}
		for _, port := range container.PublishedPorts {
			if port.Binding == model.BindingPublic {
				seenPublicPorts[fmt.Sprintf("%s/%d", port.Protocol, port.HostPort)] = struct{}{}
				findings = append(findings, publicDockerFinding(container, port, input.Firewall))
				continue
			}
			findings = append(findings, localDockerFinding(container, port))
		}
	}

	if input.Compose != nil {
		for _, service := range input.Compose.Services {
			if strings.EqualFold(service.NetworkMode, "host") {
				findings = append(findings, composeHostNetworkFinding(service))
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
			if finding, ok := publicListenerFinding(item); ok {
				findings = append(findings, finding)
			}
		}
	}

	if !input.NoFirewall && input.Firewall.UFWStatus == "unknown" {
		findings = append(findings, firewallUnknownFinding())
	}
	if !input.NoDocker && !input.DockerOK {
		findings = append(findings, dockerUnavailableFinding())
	}
	if !input.NoDocker && input.DockerOK && !hasPublishedDockerPorts(input.Docker) {
		findings = append(findings, model.Finding{
			ID:       "EG-INFO-DOCKER-NO-PUBLISHED-PORTS",
			Title:    "No Docker published ports were found",
			Severity: model.SeverityInfo,
			Reason:   "Docker discovery completed and did not find host-published container ports.",
			Impact:   "ExposeGuard did not identify public Docker bindings from Docker metadata.",
			Evidence: []string{"docker ps and docker inspect completed without published port mappings"},
			Fixes:    []string{"No change is needed if services are intentionally internal or not running."},
		})
	}

	sortFindings(findings)
	assignIDs(findings)
	return findings
}

func hasPublishedDockerPorts(containers []docker.Container) bool {
	for _, container := range containers {
		if len(container.PublishedPorts) > 0 {
			return true
		}
	}
	return false
}

func dockerUnavailableFinding() model.Finding {
	return model.Finding{
		ID:       "EG-INFO-DOCKER-UNAVAILABLE",
		Title:    "Docker discovery is unavailable",
		Severity: model.SeverityInfo,
		Reason:   "ExposeGuard could not complete Docker discovery on this host.",
		Impact:   "Docker-published services may be missing from this scan.",
		Fixes:    []string{"Run on a host with Docker CLI access, or use --no-docker when Docker is intentionally out of scope."},
	}
}

func publicDockerFinding(container docker.Container, port docker.PublishedPort, fw firewall.State) model.Finding {
	service := identifyService(container.Name, container.Image, port.HostPort, port.ContainerPort)
	evidence := []string{
		fmt.Sprintf("container %s publishes %s:%d->%d/%s", container.Name, port.HostIP, port.HostPort, port.ContainerPort, port.Protocol),
	}
	if fw.UFWStatus != "" {
		evidence = append(evidence, "ufw status: "+fw.UFWStatus)
	}
	if fw.HasDockerChain {
		evidence = append(evidence, "iptables DOCKER chain detected")
	}
	if fw.HasDockerUserChain {
		evidence = append(evidence, "iptables DOCKER-USER chain detected")
	}

	base := model.Finding{
		ServiceName:   service.Name,
		ContainerName: container.Name,
		Image:         container.Image,
		Port:          port.HostPort,
		Protocol:      port.Protocol,
		Binding:       model.BindingDescription(port.HostIP, port.HostPort),
		Evidence:      evidence,
	}

	if service.Critical {
		base.Title = service.Display + " is publicly exposed"
		base.Severity = model.SeverityCritical
		base.Reason = fmt.Sprintf("%s is bound to a public interface on port %d.", service.Display, port.HostPort)
		base.Impact = "This service is commonly targeted and should not be reachable directly from the internet without a deliberate access control layer."
		base.Fixes = databaseFixes(port)
		return base
	}
	if service.High {
		base.Title = service.Display + " is publicly exposed"
		base.Severity = model.SeverityHigh
		base.Reason = fmt.Sprintf("%s is reachable on a public binding.", service.Display)
		base.Impact = "Administrative and observability interfaces often expose sensitive operations or internal data."
		base.Fixes = adminFixes(port)
		return base
	}
	if hasAdminKeyword(container.Name, container.Image) {
		base.Title = "Public service name looks administrative"
		base.Severity = model.SeverityHigh
		base.Reason = "The container name or image includes dashboard, admin, panel or manager keywords and is published publicly."
		base.Impact = "An administrative interface may be reachable without the reverse proxy or access policy you expected."
		base.Fixes = adminFixes(port)
		return base
	}
	if docker.HasDockerSocket(container) && looksDashboard(container.Name, container.Image, port.HostPort) {
		base.Title = "Public dashboard has the Docker socket mounted"
		base.Severity = model.SeverityHigh
		base.Reason = "The service is public and can access /var/run/docker.sock from the container."
		base.Impact = "A compromise of the dashboard can become host-level container control."
		base.Fixes = []string{
			"Remove the Docker socket mount unless the service absolutely requires it.",
			"Bind the service to 127.0.0.1 and place it behind a protected reverse proxy.",
		}
		return base
	}
	if isDirectHTTP(port.HostPort, container.Name, container.Image, container.Labels) {
		base.Title = "HTTP service is exposed directly"
		base.Severity = model.SeverityMedium
		base.Reason = "HTTP or HTTPS is published publicly without a known reverse proxy context in the container metadata."
		base.Impact = "The service may be reachable directly instead of through the expected TLS, authentication and routing layer."
		base.Fixes = []string{
			"Confirm this container is intended to be the public reverse proxy.",
			"Otherwise bind the port to 127.0.0.1 or remove the published port.",
		}
		return base
	}

	base.Title = "Unknown public Docker service"
	base.Severity = model.SeverityMedium
	base.Reason = "A Docker published port is bound to a public interface."
	base.Impact = "The service may be reachable from the internet depending on host networking and firewall policy."
	base.Fixes = []string{
		"Bind the port to 127.0.0.1 if it only needs local reverse proxy access.",
		"Restrict access with a host firewall rule in DOCKER-USER or equivalent.",
		"Remove the published port if the service should be internal only.",
	}
	if fw.UFWStatus == "active" {
		base.Reason += " UFW is active, but Docker-published ports can bypass simple UFW expectations."
	}
	return base
}

func localDockerFinding(container docker.Container, port docker.PublishedPort) model.Finding {
	return model.Finding{
		Title:         "Docker service is bound to localhost",
		Severity:      model.SeverityInfo,
		ServiceName:   identifyService(container.Name, container.Image, port.HostPort, port.ContainerPort).Name,
		ContainerName: container.Name,
		Image:         container.Image,
		Port:          port.HostPort,
		Protocol:      port.Protocol,
		Binding:       model.BindingDescription(port.HostIP, port.HostPort),
		Reason:        "The published port is bound to a loopback address.",
		Impact:        "The service should only be reachable from the host or local reverse proxy.",
		Evidence:      []string{fmt.Sprintf("container %s publishes %s:%d->%d/%s", container.Name, port.HostIP, port.HostPort, port.ContainerPort, port.Protocol)},
		Fixes:         []string{"No change is needed if localhost-only access is intentional."},
	}
}

func internalExposure(container docker.Container) model.Finding {
	var exposed []string
	for _, port := range container.ExposedPorts {
		exposed = append(exposed, fmt.Sprintf("%d/%s", port.Port, port.Protocol))
	}
	return model.Finding{
		Title:         "Docker service exposes internal ports only",
		Severity:      model.SeverityInfo,
		ContainerName: container.Name,
		Image:         container.Image,
		Reason:        "The container declares exposed ports but Docker did not publish them to the host.",
		Impact:        "The service is not exposed through Docker port publishing.",
		Evidence:      []string{"exposed ports: " + strings.Join(exposed, ", ")},
		Fixes:         []string{"No change is needed if the service is meant to stay internal."},
	}
}

func composeHostNetworkFinding(service compose.Service) model.Finding {
	return model.Finding{
		Title:       "Compose service uses host networking",
		Severity:    model.SeverityMedium,
		ServiceName: service.Name,
		Image:       service.Image,
		Reason:      "network_mode: host places the service directly on the host network namespace.",
		Impact:      "Ports opened by the process can become host listeners without Docker published port metadata.",
		Evidence:    []string{"compose service " + service.Name + " sets network_mode: host"},
		Fixes: []string{
			"Use bridge networking and publish only the ports that must be reachable.",
			"Run exposeguard with listener checks enabled to confirm host-level listeners.",
		},
	}
}

func publicListenerFinding(item listener.Listener) (model.Finding, bool) {
	service := identifyService(item.Process, item.Process, item.Port, item.Port)
	if !service.Critical && !service.High {
		return model.Finding{}, false
	}
	finding := model.Finding{
		Title:       service.Display + " listener is public",
		Severity:    model.SeverityHigh,
		ServiceName: service.Name,
		Port:        item.Port,
		Protocol:    item.Protocol,
		Binding:     model.BindingDescription(item.LocalIP, item.Port),
		Reason:      fmt.Sprintf("A host listener is bound to a public interface on port %d.", item.Port),
		Impact:      "The process may be reachable from networks that can route to this host.",
		Evidence:    []string{fmt.Sprintf("ss reports %s listener on %s:%d", item.Protocol, item.LocalIP, item.Port)},
		Fixes:       []string{"Bind the service to 127.0.0.1 or restrict access with host firewall policy."},
	}
	if service.Critical {
		finding.Severity = model.SeverityCritical
	}
	return finding, true
}

func firewallUnknownFinding() model.Finding {
	return model.Finding{
		Title:    "Firewall state is unknown",
		Severity: model.SeverityInfo,
		Reason:   "ExposeGuard could not determine host firewall state from available commands.",
		Impact:   "Exposure decisions may need manual confirmation against your firewall backend.",
		Fixes:    []string{"Run with sufficient permissions to read ufw, iptables-save and nft list ruleset output."},
	}
}

type serviceMatch struct {
	Name     string
	Display  string
	Critical bool
	High     bool
}

func identifyService(name, image string, hostPort, containerPort int) serviceMatch {
	text := strings.ToLower(name + " " + image)
	port := hostPort
	if containerPort > 0 {
		port = containerPort
	}
	matches := []struct {
		name     string
		display  string
		port     int
		keywords []string
		critical bool
	}{
		{"postgresql", "PostgreSQL", 5432, []string{"postgres", "postgresql"}, true},
		{"mysql", "MySQL or MariaDB", 3306, []string{"mysql", "mariadb"}, true},
		{"redis", "Redis", 6379, []string{"redis"}, true},
		{"mongodb", "MongoDB", 27017, []string{"mongo", "mongodb"}, true},
		{"docker-daemon", "Docker daemon", 2375, []string{"docker"}, true},
		{"docker-daemon", "Docker daemon", 2376, []string{"docker"}, true},
		{"portainer", "Portainer", 9000, []string{"portainer"}, false},
		{"portainer", "Portainer", 9443, []string{"portainer"}, false},
		{"grafana", "Grafana", 3000, []string{"grafana"}, false},
		{"prometheus", "Prometheus", 9090, []string{"prometheus"}, false},
		{"elasticsearch", "Elasticsearch", 9200, []string{"elastic", "elasticsearch"}, false},
		{"rabbitmq-management", "RabbitMQ management", 15672, []string{"rabbitmq"}, false},
	}
	for _, match := range matches {
		if port == match.port || hasAny(text, match.keywords) && (hostPort == match.port || containerPort == match.port) {
			return serviceMatch{Name: match.name, Display: match.display, Critical: match.critical, High: !match.critical}
		}
	}
	return serviceMatch{Name: "unknown", Display: "Unknown service"}
}

func hasAdminKeyword(name, image string) bool {
	return hasAny(strings.ToLower(name+" "+image), []string{"dashboard", "admin", "panel", "manager"})
}

func looksDashboard(name, image string, port int) bool {
	return hasAdminKeyword(name, image) || port == 3000 || port == 9000 || port == 9443
}

func isDirectHTTP(port int, name, image string, labels map[string]string) bool {
	if port != 80 && port != 443 && port != 8080 && port != 8443 {
		return false
	}
	text := strings.ToLower(name + " " + image)
	if hasAny(text, []string{"nginx", "caddy", "traefik", "haproxy", "envoy", "apache"}) {
		return false
	}
	for key := range labels {
		if hasAny(strings.ToLower(key), []string{"traefik", "caddy"}) {
			return false
		}
	}
	return true
}

func hasAny(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

func databaseFixes(port docker.PublishedPort) []string {
	return []string{
		fmt.Sprintf("Change the compose port mapping to \"127.0.0.1:%d:%d\" if only local access is needed.", port.HostPort, port.ContainerPort),
		"Remove the published port and place dependent services on the same Docker network.",
		"If remote access is required, restrict it with a VPN or strict source IP firewall policy.",
	}
}

func adminFixes(port docker.PublishedPort) []string {
	return []string{
		fmt.Sprintf("Bind the published port to localhost, for example \"127.0.0.1:%d:%d\".", port.HostPort, port.ContainerPort),
		"Put the interface behind a reverse proxy with TLS and authentication.",
		"Restrict direct access with a DOCKER-USER firewall rule or equivalent host policy.",
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
		return findings[i].Title < findings[j].Title
	})
}

func assignIDs(findings []model.Finding) {
	for i := range findings {
		if findings[i].ID != "" {
			continue
		}
		prefix := strings.ToUpper(string(findings[i].Severity))
		if prefix == "INFO" {
			prefix = "INFO"
		}
		findings[i].ID = fmt.Sprintf("EG-%s-%03d", prefix, i+1)
	}
}
