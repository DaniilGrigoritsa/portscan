package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = time.Second
	defaultResolveTimeout = 5 * time.Second
	defaultCancelGrace    = 100 * time.Millisecond
)

// Opens TCP connections, impelemented by *net.Dialer
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type config struct {
	concurrency    int
	connectTimeout time.Duration
	resolveTimeout time.Duration
	dialer         Dialer
	resolver       Resolver
	cancelGrace    time.Duration
}

func (c config) withDefaults() config {
	if c.concurrency == 0 {
		c.concurrency = defaultConcurrency
	}
	if c.connectTimeout == 0 {
		c.connectTimeout = defaultConnectTimeout
	}
	if c.resolveTimeout == 0 {
		c.resolveTimeout = defaultResolveTimeout
	}
	if c.dialer == nil {
		c.dialer = &net.Dialer{KeepAlive: -1}
	}
	if c.resolver == nil {
		c.resolver = net.DefaultResolver
	}
	if c.cancelGrace == 0 {
		c.cancelGrace = defaultCancelGrace
	}
	return c
}

type Option func(*config) error

// WithConcurrency sets the maximum number of simultaneously running connection attempts of one Scan call
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: concurrency must be >= 1, got %d", ErrInvalidOption, n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets the timeout of a single connection attempt
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: connect timeout must be positive, got %v", ErrInvalidOption, d)
		}
		c.connectTimeout = d
		return nil
	}
}

// WithResolveTimeout sets the timeout of resolving one DNS name
func WithResolveTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: resolve timeout must be positive, got %v", ErrInvalidOption, d)
		}
		c.resolveTimeout = d
		return nil
	}
}

// WithDialer replaces the default net.Dialer
func WithDialer(d Dialer) Option {
	return func(c *config) error {
		if d == nil {
			return fmt.Errorf("%w: nil dialer", ErrInvalidOption)
		}
		c.dialer = d
		return nil
	}
}

// WithResolver replaces net.DefaultResolver
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		if r == nil {
			return fmt.Errorf("%w: nil resolver", ErrInvalidOption)
		}
		c.resolver = r
		return nil
	}
}
