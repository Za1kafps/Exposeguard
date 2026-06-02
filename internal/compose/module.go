package compose

import "go.uber.org/fx"

var Module = fx.Module(
	"compose",
	fx.Provide(NewParser),
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) ParseFile(path string) (Project, error) {
	return ParseFile(path)
}
