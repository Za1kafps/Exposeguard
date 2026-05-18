package model

import "testing"

func TestClassifyBinding(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want BindingClass
	}{
		{name: "empty is public", ip: "", want: BindingPublic},
		{name: "all IPv4 is public", ip: "0.0.0.0", want: BindingPublic},
		{name: "all IPv6 is public", ip: "::", want: BindingPublic},
		{name: "localhost name is local", ip: "localhost", want: BindingLocal},
		{name: "localhost IPv4 is local", ip: "127.0.0.1", want: BindingLocal},
		{name: "localhost IPv4 range is local", ip: "127.0.1.1", want: BindingLocal},
		{name: "localhost IPv6 is local", ip: "::1", want: BindingLocal},
		{name: "private IP is public exposure", ip: "10.0.0.20", want: BindingPublic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyBinding(tt.ip); got != tt.want {
				t.Fatalf("ClassifyBinding(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestFailsThreshold(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityMedium},
		{Severity: SeverityInfo},
	}
	tests := []struct {
		name      string
		threshold FailThreshold
		want      bool
	}{
		{name: "none never fails", threshold: FailNone, want: false},
		{name: "critical does not match medium", threshold: FailCritical, want: false},
		{name: "medium matches medium", threshold: FailMedium, want: true},
		{name: "low matches medium", threshold: FailLow, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FailsThreshold(findings, tt.threshold); got != tt.want {
				t.Fatalf("FailsThreshold() = %v, want %v", got, tt.want)
			}
		})
	}
}
