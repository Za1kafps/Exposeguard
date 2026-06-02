package intent

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/model"
)

type Input struct {
	Compose       *compose.Service
	Container     *docker.Container
	HostPort      int
	ContainerPort int
}

func Infer(input Input) model.ServiceIntent {
	scores := map[string]int{}
	signals := map[string]map[string]struct{}{}
	add := func(category string, weight int, signal string) {
		scores[category] += weight
		if signals[category] == nil {
			signals[category] = map[string]struct{}{}
		}
		signals[category][signal] = struct{}{}
	}

	text := normalizedText(input)
	envKeys := normalizedEnvKeys(input)
	ports := []int{input.HostPort, input.ContainerPort}
	for _, port := range ports {
		switch port {
		case 5432, 3306, 27017:
			add("database", 3, fmt.Sprintf("known database port %d", port))
		case 6379, 11211:
			add("cache", 3, fmt.Sprintf("known cache port %d", port))
		case 5672, 15672:
			add("queue", 2, fmt.Sprintf("known queue port %d", port))
		case 9001:
			add("object-storage", 2, fmt.Sprintf("known object storage/admin port %d", port))
		case 9200, 9300, 7700, 8983:
			add("search", 2, fmt.Sprintf("known search port %d", port))
		case 3000, 9000, 9443, 9090:
			add("dashboard", 2, fmt.Sprintf("known dashboard/metrics port %d", port))
		case 80, 443:
			add("public-web", 2, fmt.Sprintf("standard public web port %d", port))
			add("reverse-proxy", 1, fmt.Sprintf("standard edge port %d", port))
		case 8080, 8443:
			add("public-web", 1, fmt.Sprintf("common HTTP port %d", port))
			add("reverse-proxy", 1, fmt.Sprintf("common proxy port %d", port))
		case 9091, 9100, 9115, 9187:
			add("metrics", 2, fmt.Sprintf("known metrics port %d", port))
		}
	}

	tokenRules := []struct {
		category string
		weight   int
		tokens   []string
	}{
		{"database", 3, []string{"postgres", "postgresql", "mysql", "mariadb", "mongo", "mongodb", "database", "db"}},
		{"cache", 3, []string{"redis", "memcached", "cache"}},
		{"queue", 3, []string{"rabbitmq", "amqp", "nats", "kafka", "queue"}},
		{"object-storage", 3, []string{"minio", "s3", "object-storage", "object_storage"}},
		{"search", 3, []string{"elastic", "elasticsearch", "opensearch", "meilisearch", "solr", "search"}},
		{"dashboard", 3, []string{"grafana", "portainer", "dashboard", "admin", "panel", "manager"}},
		{"reverse-proxy", 4, []string{"traefik", "caddy", "nginx-proxy-manager", "nginx proxy manager", "nginx-proxy", "haproxy", "reverse-proxy", "reverse_proxy"}},
		{"reverse-proxy", 3, []string{"nginx", "caddy", "proxy"}},
		{"public-web", 2, []string{"frontend", "web", "www", "httpd", "apache"}},
		{"internal-api", 2, []string{"api", "backend", "server", "service", "worker", "internal"}},
		{"metrics", 3, []string{"prometheus", "alertmanager", "loki", "tempo", "metrics", "exporter"}},
	}
	for _, rule := range tokenRules {
		for _, token := range rule.tokens {
			if containsToken(text, token) {
				add(rule.category, rule.weight, "matched token "+token)
			}
		}
	}

	for _, key := range envKeys {
		switch {
		case strings.HasPrefix(key, "POSTGRES_") || strings.HasPrefix(key, "MYSQL_") || strings.HasPrefix(key, "MARIADB_") || strings.HasPrefix(key, "MONGO_") || key == "DATABASE_URL":
			add("database", 2, "environment key "+key)
		case strings.HasPrefix(key, "REDIS_"):
			add("cache", 2, "environment key "+key)
		case strings.HasPrefix(key, "RABBITMQ_"):
			add("queue", 2, "environment key "+key)
		case strings.HasPrefix(key, "S3_") || strings.HasPrefix(key, "AWS_"):
			add("object-storage", 1, "environment key "+key)
		case strings.HasPrefix(key, "ELASTIC_") || strings.HasPrefix(key, "OPENSEARCH_"):
			add("search", 2, "environment key "+key)
		}
	}

	for key := range labels(input) {
		lower := strings.ToLower(key)
		switch {
		case strings.HasPrefix(lower, "traefik.") || strings.HasPrefix(lower, "caddy.") || strings.HasPrefix(lower, "nginx.") || strings.HasPrefix(lower, "nginx-proxy."):
			add("reverse-proxy", 3, "reverse proxy label "+key)
		case strings.Contains(lower, "metrics"):
			add("metrics", 1, "metrics label "+key)
		}
	}

	category, score := topCategory(scores)
	if category == "" || score == 0 {
		return model.ServiceIntent{Category: "unknown", Confidence: "low"}
	}
	return model.ServiceIntent{
		Category:   category,
		Confidence: confidence(score),
		Signals:    sortedSignals(signals[category]),
	}
}

func IsInternalLike(intent model.ServiceIntent) bool {
	switch intent.Category {
	case "database", "cache", "queue", "object-storage", "search", "dashboard", "internal-api", "metrics":
		return true
	default:
		return false
	}
}

func normalizedText(input Input) string {
	var parts []string
	if input.Compose != nil {
		parts = append(parts, input.Compose.Name, input.Compose.Image, input.Compose.Command, input.Compose.Healthcheck)
		parts = append(parts, input.Compose.Ports...)
		parts = append(parts, input.Compose.Expose...)
		parts = append(parts, input.Compose.Volumes...)
	}
	if input.Container != nil {
		parts = append(parts, input.Container.Name, input.Container.Image)
		parts = append(parts, input.Container.Command...)
		for _, mount := range input.Container.Mounts {
			parts = append(parts, mount.Destination)
		}
		for _, bind := range input.Container.Binds {
			parts = append(parts, bind)
		}
	}
	for key, value := range labels(input) {
		parts = append(parts, key, value)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func normalizedEnvKeys(input Input) []string {
	seen := map[string]struct{}{}
	if input.Compose != nil {
		for _, key := range input.Compose.EnvironmentKeys {
			seen[strings.ToUpper(key)] = struct{}{}
		}
	}
	if input.Container != nil {
		for _, key := range input.Container.EnvironmentKeys {
			seen[strings.ToUpper(key)] = struct{}{}
		}
	}
	var keys []string
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func labels(input Input) map[string]string {
	values := map[string]string{}
	if input.Compose != nil {
		for key, value := range input.Compose.Labels {
			values[key] = value
		}
	}
	if input.Container != nil {
		for key, value := range input.Container.Labels {
			values[key] = value
		}
	}
	return values
}

func containsToken(text, token string) bool {
	if _, err := strconv.Atoi(token); err == nil {
		return strings.Contains(text, token)
	}
	return strings.Contains(text, token)
}

func topCategory(scores map[string]int) (string, int) {
	order := []string{"database", "cache", "queue", "object-storage", "search", "dashboard", "reverse-proxy", "public-web", "internal-api", "metrics", "unknown"}
	best := ""
	bestScore := 0
	for _, category := range order {
		if scores[category] > bestScore {
			best = category
			bestScore = scores[category]
		}
	}
	return best, bestScore
}

func confidence(score int) string {
	switch {
	case score >= 4:
		return "high"
	case score >= 2:
		return "medium"
	default:
		return "low"
	}
}

func sortedSignals(values map[string]struct{}) []string {
	signals := make([]string, 0, len(values))
	for signal := range values {
		signals = append(signals, signal)
	}
	sort.Strings(signals)
	return signals
}
