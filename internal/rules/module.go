package rules

import (
	"github.com/Za1kafps/exposeguard/internal/model"
	"go.uber.org/fx"
)

var Module = fx.Module(
	"rules",
	fx.Provide(NewEvaluator),
)

type Evaluator struct{}

func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

func (e *Evaluator) Evaluate(input Input) []model.Finding {
	return Evaluate(input)
}
