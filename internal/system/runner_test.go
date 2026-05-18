package system

import (
	"context"
	"testing"
)

func TestMockRunner(t *testing.T) {
	runner := NewMockRunner(map[string]MockResponse{
		CommandKey("docker", "ps"): {Result: Result{Stdout: "ok\n"}},
	})
	result, err := runner.Run(context.Background(), "docker", "ps")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Stdout != "ok\n" {
		t.Fatalf("stdout = %q, want ok", result.Stdout)
	}
	if len(runner.Calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(runner.Calls))
	}
	if runner.Calls[0].Name != "docker" || runner.Calls[0].Args[0] != "ps" {
		t.Fatalf("unexpected call: %#v", runner.Calls[0])
	}
}
