package report

import (
	"github.com/Za1kafps/exposeguard/internal/model"
	"go.uber.org/fx"
)

var Module = fx.Module(
	"report",
	fx.Provide(NewRenderer),
)

type Renderer struct{}

func NewRenderer() *Renderer {
	return &Renderer{}
}

func (r *Renderer) Render(format Format, report model.Report) ([]byte, error) {
	return Render(format, report)
}

func (r *Renderer) RenderWithOptions(format Format, report model.Report, options RenderOptions) ([]byte, error) {
	return RenderWithOptions(format, report, options)
}
