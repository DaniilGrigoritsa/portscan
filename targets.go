package portscan

import (
	"errors"
	"net/netip"
	"strings"
)

// a validated entry of the host list.
type target struct {
	host string
	key  string // normalized form, used to drop duplicates and for DNS lookups
	addr netip.Addr
}

func parseTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}
	targets := make([]target, 0, len(hosts))
	var errs []error
	for _, h := range hosts {
		t, err := parseTarget(h)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		targets = append(targets, t)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return targets, nil
}

func parseTarget(raw string) (target, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return target{}, &HostError{Host: raw, Err: ErrEmptyHost}
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		addr = addr.Unmap()
		return target{host: h, key: addr.String(), addr: addr}, nil
	}
	if !validHostname(h) {
		return target{}, &HostError{Host: raw, Err: ErrInvalidHost}
	}
	key := strings.ToLower(strings.TrimSuffix(h, "."))
	return target{host: h, key: key}, nil
}

func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return !allDigits(labels[len(labels)-1])
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
