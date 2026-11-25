package portscan

import (
	"errors"
	"testing"
)

func TestPorts(t *testing.T) {
	tests := []struct {
		name    string
		ports   Ports
		wantErr error
		wantStr string
		wantLen int
	}{
		{name: "single port", ports: List(80), wantStr: "80", wantLen: 1},
		{name: "range", ports: Range(1, 1000), wantStr: "1-1000", wantLen: 1000},
		{name: "range of one", ports: Range(22, 22), wantStr: "22", wantLen: 1},
		{name: "full range", ports: Range(1, 65535), wantStr: "1-65535", wantLen: 65535},
		{name: "unsorted list", ports: List(443, 22, 80), wantStr: "22,80,443", wantLen: 3},
		{name: "duplicates", ports: List(80, 80, 443, 80), wantStr: "80,443", wantLen: 2},
		{name: "adjacent singles are joined", ports: List(1, 2, 3, 5), wantStr: "1-3,5", wantLen: 4},
		{
			name:    "merge overlapping and adjacent",
			ports:   Merge(Range(1, 10), Range(5, 20), List(21, 100)),
			wantStr: "1-21,100", wantLen: 22,
		},
		{name: "merge contained range", ports: Merge(Range(1, 100), Range(10, 20)), wantStr: "1-100", wantLen: 100},
		{name: "merge with duplicates", ports: Merge(List(80), List(80), Range(80, 80)), wantStr: "80", wantLen: 1},
		{name: "boundary 65535", ports: List(65535), wantStr: "65535", wantLen: 1},
		{name: "empty list is valid but empty", ports: List(), wantStr: "", wantLen: 0},
		{name: "empty merge", ports: Merge(), wantStr: "", wantLen: 0},
		{name: "zero value", ports: Ports{}, wantStr: "", wantLen: 0},

		{name: "port 0", ports: List(0), wantErr: ErrInvalidPort},
		{name: "port 0 in range", ports: Range(0, 10), wantErr: ErrInvalidPort},
		{name: "port above 65535", ports: List(65536), wantErr: ErrInvalidPort},
		{name: "range above 65535", ports: Range(1, 65536), wantErr: ErrInvalidPort},
		{name: "negative port", ports: List(-1), wantErr: ErrInvalidPort},
		{name: "reversed range", ports: Range(1000, 1), wantErr: ErrInvalidRange},
		{name: "invalid in the middle of list", ports: List(80, 0, 443), wantErr: ErrInvalidPort},
		{name: "merge propagates error", ports: Merge(Range(1, 10), Range(10, 1)), wantErr: ErrInvalidRange},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != nil {
				if err := tt.ports.Err(); !errors.Is(err, tt.wantErr) {
					t.Fatalf("Err() = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err := tt.ports.Err(); err != nil {
				t.Fatalf("Err() = %v, want nil", err)
			}
			if got := tt.ports.String(); got != tt.wantStr {
				t.Errorf("String() = %q, want %q", got, tt.wantStr)
			}
			if got := tt.ports.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestPortsReportsAllErrors(t *testing.T) {
	err := List(0, 70000).Err()
	if !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("want ErrInvalidPort, got %v", err)
	}
	err = Merge(List(0), Range(5, 1)).Err()
	if !errors.Is(err, ErrInvalidPort) || !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("want both ErrInvalidPort and ErrInvalidRange, got %v", err)
	}
}

func TestMergeDoesNotAliasInputs(t *testing.T) {
	a := Range(1, 10)
	b := Range(20, 30)
	_ = Merge(a, b, List(15))
	if a.String() != "1-10" || b.String() != "20-30" {
		t.Fatalf("inputs were modified: %s, %s", a, b)
	}
}
