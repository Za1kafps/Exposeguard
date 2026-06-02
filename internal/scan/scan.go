package scan

import (
	"context"
	"os"
	"time"

	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/firewall"
	"github.com/Za1kafps/exposeguard/internal/listener"
	"github.com/Za1kafps/exposeguard/internal/model"
	"github.com/Za1kafps/exposeguard/internal/rules"
	"github.com/Za1kafps/exposeguard/internal/system"
	"go.uber.org/fx"
)

const Version = "0.1.0"

var Module = fx.Module(
	"scan",
	fx.Provide(
		NewClock,
		NewHostnameProvider,
		NewService,
	),
)

type Options struct {
	ComposeFile string
	NoDocker    bool
	NoFirewall  bool
	NoListeners bool
	Verbose     bool
}

type Clock func() time.Time

type HostnameProvider func() (string, error)

type Service struct {
	docker   *docker.Discovery
	compose  *compose.Parser
	firewall *firewall.Discovery
	listener *listener.Discovery
	rules    *rules.Evaluator
	clock    Clock
	hostname HostnameProvider
}

func NewClock() Clock {
	return time.Now
}

func NewHostnameProvider() HostnameProvider {
	return os.Hostname
}

func NewService(
	dockerDiscovery *docker.Discovery,
	composeParser *compose.Parser,
	firewallDiscovery *firewall.Discovery,
	listenerDiscovery *listener.Discovery,
	evaluator *rules.Evaluator,
	clock Clock,
	hostname HostnameProvider,
) *Service {
	return &Service{
		docker:   dockerDiscovery,
		compose:  composeParser,
		firewall: firewallDiscovery,
		listener: listenerDiscovery,
		rules:    evaluator,
		clock:    clock,
		hostname: hostname,
	}
}

func Run(ctx context.Context, runner system.Runner, options Options) (model.Report, error) {
	service := NewService(
		docker.NewDiscovery(runner),
		compose.NewParser(),
		firewall.NewDiscovery(runner),
		listener.NewDiscovery(runner),
		rules.NewEvaluator(),
		NewClock(),
		NewHostnameProvider(),
	)
	return service.Run(ctx, options)
}

func (s *Service) Run(ctx context.Context, options Options) (model.Report, error) {
	var warnings []model.Warning

	var dockerResult docker.Result
	if !options.NoDocker {
		dockerResult = s.docker.Discover(ctx)
		warnings = append(warnings, dockerResult.Warnings...)
	}

	var composeProject *compose.Project
	if options.ComposeFile != "" {
		project, err := s.compose.ParseFile(options.ComposeFile)
		if err != nil {
			return model.Report{}, err
		}
		composeProject = &project
	}

	var firewallResult firewall.Result
	if !options.NoFirewall {
		firewallResult = s.firewall.Discover(ctx)
		warnings = append(warnings, firewallResult.Warnings...)
	}

	var listenerResult listener.Result
	if !options.NoListeners {
		listenerResult = s.listener.Discover(ctx)
		warnings = append(warnings, listenerResult.Warnings...)
	}

	findings := s.rules.Evaluate(rules.Input{
		Docker:      dockerResult.Containers,
		Compose:     composeProject,
		Firewall:    firewallResult.State,
		Listeners:   listenerResult.Listeners,
		NoDocker:    options.NoDocker,
		NoFirewall:  options.NoFirewall,
		NoListeners: options.NoListeners,
		DockerOK:    options.NoDocker || dockerResult.Available,
	})

	hostname, _ := s.hostname()
	report := model.Report{
		Metadata: model.Metadata{
			Tool:        "exposeguard",
			Version:     Version,
			GeneratedAt: s.clock(),
			Hostname:    hostname,
		},
		Findings: findings,
		Warnings: warnings,
		Capabilities: model.ScannerCapabilities{
			Docker:    !options.NoDocker,
			Compose:   options.ComposeFile != "",
			Firewall:  !options.NoFirewall,
			Listeners: !options.NoListeners,
		},
	}
	report.Summary = model.BuildSummary(findings)
	return report, nil
}
