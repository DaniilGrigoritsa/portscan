package portscan

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const maxPort = 65535

// an inclusive range of ports
type span struct{ lo, hi int }

type Ports struct {
	spans []span // sorted, non-overlapping, non-adjacent
	err   error
}

func Range(first, last int) Ports {
	if err := checkPort(first); err != nil {
		return Ports{err: err}
	}
	if err := checkPort(last); err != nil {
		return Ports{err: err}
	}
	if first > last {
		return Ports{err: fmt.Errorf("%w: %d-%d", ErrInvalidRange, first, last)}
	}
	return Ports{spans: []span{{first, last}}}
}

func List(ports ...int) Ports {
	spans := make([]span, 0, len(ports))
	var errs []error
	for _, p := range ports {
		if err := checkPort(p); err != nil {
			errs = append(errs, err)
			continue
		}
		spans = append(spans, span{p, p})
	}
	if len(errs) > 0 {
		return Ports{err: errors.Join(errs...)}
	}
	return Ports{spans: normalize(spans)}
}

func Merge(sets ...Ports) Ports {
	var spans []span
	var errs []error
	for _, s := range sets {
		if s.err != nil {
			errs = append(errs, s.err)
			continue
		}
		spans = append(spans, s.spans...)
	}
	if len(errs) > 0 {
		return Ports{err: errors.Join(errs...)}
	}
	return Ports{spans: normalize(spans)}
}

func (p Ports) Err() error { return p.err }

func (p Ports) Len() int {
	n := 0
	for _, s := range p.spans {
		n += s.hi - s.lo + 1
	}
	return n
}

func (p Ports) String() string {
	parts := make([]string, 0, len(p.spans))
	for _, s := range p.spans {
		if s.lo == s.hi {
			parts = append(parts, strconv.Itoa(s.lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", s.lo, s.hi))
		}
	}
	return strings.Join(parts, ",")
}

func checkPort(p int) error {
	if p < 1 || p > maxPort {
		return fmt.Errorf("%w: %d (must be in 1..%d)", ErrInvalidPort, p, maxPort)
	}
	return nil
}

func normalize(spans []span) []span {
	if len(spans) == 0 {
		return nil
	}
	slices.SortFunc(spans, func(a, b span) int { return a.lo - b.lo })
	out := spans[:1]
	for _, s := range spans[1:] {
		last := &out[len(out)-1]
		if s.lo <= last.hi+1 {
			last.hi = max(last.hi, s.hi)
			continue
		}
		out = append(out, s)
	}
	return out
}
