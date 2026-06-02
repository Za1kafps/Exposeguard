package app

import (
	"github.com/Za1kafps/exposeguard/internal/compose"
	"github.com/Za1kafps/exposeguard/internal/docker"
	"github.com/Za1kafps/exposeguard/internal/firewall"
	"github.com/Za1kafps/exposeguard/internal/listener"
	"github.com/Za1kafps/exposeguard/internal/report"
	"github.com/Za1kafps/exposeguard/internal/rules"
	"github.com/Za1kafps/exposeguard/internal/scan"
	"github.com/Za1kafps/exposeguard/internal/system"
	"go.uber.org/fx"
)

var Module = fx.Module(
	"app",
	system.Module,
	docker.Module,
	compose.Module,
	firewall.Module,
	listener.Module,
	rules.Module,
	report.Module,
	scan.Module,
	fx.Provide(New),
)
