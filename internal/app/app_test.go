package app

import (
	"context"
	"testing"
)

func TestModuleBuilds(t *testing.T) {
	ctx := context.Background()
	application, stop, err := NewDefault(ctx)
	if err != nil {
		t.Fatalf("NewDefault() error = %v", err)
	}
	if application == nil {
		t.Fatal("application is nil")
	}
	if err := stop(ctx); err != nil {
		t.Fatalf("stop application: %v", err)
	}
}
