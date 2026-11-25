package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func opErr(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", err)}
}

func TestClassify(t *testing.T) {
	live := context.Background()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want State
	}{
		{"refused", live, opErr(syscall.ECONNREFUSED), StateClosed},
		{"refused wrapped", live, fmt.Errorf("wrap: %w", opErr(syscall.ECONNREFUSED)), StateClosed},
		{"network unreachable", live, opErr(syscall.ENETUNREACH), StateUnreachable},
		{"host unreachable", live, opErr(syscall.EHOSTUNREACH), StateUnreachable},
		{"network down", live, opErr(syscall.ENETDOWN), StateUnreachable},
		{"host down", live, opErr(syscall.EHOSTDOWN), StateUnreachable},
		{"deadline exceeded", live, context.DeadlineExceeded, StateTimeout},
		{"os deadline", live, &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, StateTimeout},
		{"net.Error timeout", live, &net.DNSError{IsTimeout: true}, StateTimeout},
		{"canceled error", live, context.Canceled, StateCanceled},
		{"scan context done", canceled, context.DeadlineExceeded, StateCanceled},
		{"other syscall error", live, opErr(syscall.EMFILE), StateError},
		{"addr not available", live, opErr(syscall.EADDRNOTAVAIL), StateError},
		{"plain error", live, errors.New("connection refused"), StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.ctx, tt.err); got != tt.want {
				t.Errorf("classify = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStateString(t *testing.T) {
	want := map[State]string{
		StateOpen: "open", StateClosed: "closed", StateTimeout: "timeout",
		StateUnreachable: "unreachable", StateCanceled: "canceled", StateError: "error",
		State(0): "unknown", State(200): "unknown",
	}
	for s, w := range want {
		if s.String() != w {
			t.Errorf("State(%d).String() = %q, want %q", s, s.String(), w)
		}
		b, err := s.MarshalText()
		if err != nil || string(b) != w {
			t.Errorf("State(%d).MarshalText() = %q, %v", s, b, err)
		}
	}
}
