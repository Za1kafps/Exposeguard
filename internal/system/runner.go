package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

type ExecRunner struct {
	Timeout time.Duration
}

func NewExecRunner() ExecRunner {
	return ExecRunner{Timeout: 15 * time.Second}
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: 0}
	if cmdCtx.Err() != nil {
		return result, fmt.Errorf("%s timed out: %w", name, cmdCtx.Err())
	}
	if err == nil {
		return result, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return result, fmt.Errorf("run %s: %w", name, err)
}

type MockRunner struct {
	Calls     []Call
	Responses map[string]MockResponse
}

type Call struct {
	Name string
	Args []string
}

type MockResponse struct {
	Result Result
	Err    error
}

func NewMockRunner(responses map[string]MockResponse) *MockRunner {
	return &MockRunner{Responses: responses}
}

func (m *MockRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	_ = ctx
	m.Calls = append(m.Calls, Call{Name: name, Args: append([]string(nil), args...)})
	key := CommandKey(name, args...)
	response, ok := m.Responses[key]
	if !ok {
		return Result{ExitCode: 127, Stderr: "mock command not found"}, nil
	}
	return response.Result, response.Err
}

func CommandKey(name string, args ...string) string {
	key := name
	for _, arg := range args {
		key += "\x00" + arg
	}
	return key
}
