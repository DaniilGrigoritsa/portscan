package portscan

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	valid := []struct{ in, wantKey string }{
		{"127.0.0.1", "127.0.0.1"},
		{" 10.0.0.1 ", "10.0.0.1"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"::ffff:1.2.3.4", "1.2.3.4"},
		{"fe80::1%eth0", "fe80::1%eth0"},
		{"localhost", "localhost"},
		{"example.com", "example.com"},
		{"EXAMPLE.com.", "example.com"},
		{"a_b.example.com", "a_b.example.com"},
		{"xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"},
		{"host1", "host1"},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.in, func(t *testing.T) {
			got, err := parseTarget(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.key != tt.wantKey {
				t.Errorf("key = %q, want %q", got.key, tt.wantKey)
			}
			if got.host != strings.TrimSpace(tt.in) {
				t.Errorf("host = %q, want %q", got.host, strings.TrimSpace(tt.in))
			}
		})
	}

	invalid := []struct {
		in   string
		want error
	}{
		{"", ErrEmptyHost},
		{"   ", ErrEmptyHost},
		{"256.1.1.1", ErrInvalidHost},
		{"1.2.3", ErrInvalidHost},
		{"1.2.3.4.5", ErrInvalidHost},
		{"host:80", ErrInvalidHost},
		{"[::1]", ErrInvalidHost},
		{"::g", ErrInvalidHost},
		{"http://example.com", ErrInvalidHost},
		{"-bad.com", ErrInvalidHost},
		{"bad-.com", ErrInvalidHost},
		{"a..b", ErrInvalidHost},
		{".", ErrInvalidHost},
		{"exa mple.com", ErrInvalidHost},
		{"пример.рф", ErrInvalidHost},
		{strings.Repeat("a", 64) + ".com", ErrInvalidHost},
		{strings.Repeat("a.", 130) + "com", ErrInvalidHost},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.in, func(t *testing.T) {
			_, err := parseTarget(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			var he *HostError
			if !errors.As(err, &he) || he.Host != tt.in {
				t.Fatalf("want *HostError for %q, got %#v", tt.in, err)
			}
		})
	}
}

func TestParseTargets(t *testing.T) {
	if _, err := parseTargets(nil); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("nil hosts: err = %v, want ErrNoHosts", err)
	}
	_, err := parseTargets([]string{"ok.example", "", "1.2.3"})
	if !errors.Is(err, ErrEmptyHost) || !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("want all problems reported, got %v", err)
	}
}
