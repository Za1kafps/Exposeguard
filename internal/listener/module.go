package listener

import (
	"context"

	"github.com/Za1kafps/exposeguard/internal/system"
	"go.uber.org/fx"
)

var Module = fx.Module(
	"listener",
	fx.Provide(NewDiscovery),
)

type Discovery struct {
	runner system.Runner
}

func NewDiscovery(runner system.Runner) *Discovery {
	return &Discovery{runner: runner}
}

func (d *Discovery) Discover(ctx context.Context) Result {
	return Discover(ctx, d.runner)
}
