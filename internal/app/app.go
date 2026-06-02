package app

import (
	"context"
	"fmt"
	"os"

	"github.com/Za1kafps/exposeguard/internal/model"
	"github.com/Za1kafps/exposeguard/internal/report"
	"github.com/Za1kafps/exposeguard/internal/scan"
	"go.uber.org/fx"
)

type Application struct {
	scanner  *scan.Service
	renderer *report.Renderer
}

type ScanRequest struct {
	Options       scan.Options
	Format        report.Format
	RenderOptions report.RenderOptions
	OutputPath    string
}

type ScanResult struct {
	Report model.Report
	Data   []byte
}

func New(scanner *scan.Service, renderer *report.Renderer) *Application {
	return &Application{scanner: scanner, renderer: renderer}
}

func NewDefault(ctx context.Context) (*Application, func(context.Context) error, error) {
	var application *Application
	fxApp := fx.New(
		Module,
		fx.Populate(&application),
		fx.NopLogger,
	)
	if err := fxApp.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("start application: %w", err)
	}
	return application, fxApp.Stop, nil
}

func (a *Application) RunScan(ctx context.Context, request ScanRequest) (ScanResult, error) {
	scanReport, err := a.scanner.Run(ctx, request.Options)
	if err != nil {
		return ScanResult{}, err
	}
	data, err := a.renderer.RenderWithOptions(request.Format, scanReport, request.RenderOptions)
	if err != nil {
		return ScanResult{}, err
	}
	if request.OutputPath != "" {
		if err := writeOutput(request.OutputPath, data); err != nil {
			return ScanResult{}, err
		}
	}
	return ScanResult{Report: scanReport, Data: data}, nil
}

func writeOutput(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
