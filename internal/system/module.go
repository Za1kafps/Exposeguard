package system

import "go.uber.org/fx"

var Module = fx.Module(
	"system",
	fx.Provide(
		fx.Annotate(
			NewExecRunner,
			fx.As(new(Runner)),
		),
	),
)
