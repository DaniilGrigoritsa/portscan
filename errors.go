package portscan

import (
	"errors"
	"fmt"
)

var (
	ErrNoHosts       = errors.New("portscan: no hosts to scan")
	ErrNoPorts       = errors.New("portscan: no ports to scan")
	ErrEmptyHost     = errors.New("portscan: empty host")
	ErrInvalidHost   = errors.New("portscan: invalid host")
	ErrInvalidPort   = errors.New("portscan: invalid port")
	ErrInvalidRange  = errors.New("portscan: invalid port range")
	ErrInvalidOption = errors.New("portscan: invalid option")
	errNoAddresses   = errors.New("no addresses found")
)

type HostError struct {
	Host string
	Err  error
}

func (e *HostError) Error() string {
	return fmt.Sprintf("%v: %q", e.Err, e.Host)
}

func (e *HostError) Unwrap() error { return e.Err }

type ResolveError struct {
	Host string
	Err  error
}

func (e *ResolveError) Error() string {
	return fmt.Sprintf("portscan: resolve %q: %v", e.Host, e.Err)
}

func (e *ResolveError) Unwrap() error { return e.Err }
