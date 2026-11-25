package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type Scanner struct {
	cfg config
}

func New(opts ...Option) (*Scanner, error) {
	var cfg config
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	return &Scanner{cfg: cfg.withDefaults()}, nil
}

func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	if ctx == nil {
		return nil, errors.New("portscan: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("portscan: scan not started: %w", err)
	}

	targets, hostsErr := parseTargets(hosts)
	portsErr := ports.err
	if portsErr == nil && len(ports.spans) == 0 {
		portsErr = ErrNoPorts
	}
	if err := errors.Join(hostsErr, portsErr); err != nil {
		return nil, err
	}

	r := &run{
		ctx:     ctx,
		cfg:     s.cfg.withDefaults(),
		targets: targets,
		ports:   ports,
		out:     make(chan Result),
	}

	go r.execute()

	return r.out, nil
}

// the state of one Scan call
type run struct {
	ctx     context.Context
	cfg     config
	targets []target
	ports   Ports
	out     chan Result
}

func (r *run) execute() {
	defer close(r.out)

	var wg sync.WaitGroup
	defer wg.Wait()

	sem := make(chan struct{}, r.cfg.concurrency)
	seenHosts := make(map[string]struct{}, len(r.targets))
	seenAddrs := make(map[netip.Addr]struct{}, len(r.targets))

	for _, t := range r.targets {
		if r.ctx.Err() != nil {
			return
		}
		if _, dup := seenHosts[t.key]; dup {
			continue
		}
		seenHosts[t.key] = struct{}{}

		addrs, took, err := r.resolve(t)
		if r.ctx.Err() != nil {
			return
		}
		if err != nil {
			r.failTarget(t, took, err)
			continue
		}
		for _, addr := range addrs {
			if _, dup := seenAddrs[addr]; dup {
				continue
			}
			seenAddrs[addr] = struct{}{}
			if !r.dispatch(&wg, sem, t.host, addr) {
				return
			}
		}
	}
}

func (r *run) dispatch(wg *sync.WaitGroup, sem chan struct{}, host string, addr netip.Addr) bool {
	for _, sp := range r.ports.spans {
		for p := sp.lo; p <= sp.hi; p++ {
			if r.ctx.Err() != nil {
				return false
			}
			select {
			case sem <- struct{}{}:
			case <-r.ctx.Done():
				return false
			}
			wg.Add(1)
			go func(port uint16) {
				defer wg.Done()
				defer func() { <-sem }()
				r.probe(host, addr, port)
			}(uint16(p))
		}
	}
	return true
}

func (r *run) resolve(t target) (addrs []netip.Addr, took time.Duration, err error) {
	if t.addr.IsValid() {
		return []netip.Addr{t.addr}, 0, nil
	}

	ctx, cancel := context.WithTimeout(r.ctx, r.cfg.resolveTimeout)
	defer cancel()

	start := time.Now()
	found, err := r.cfg.resolver.LookupNetIP(ctx, "ip", t.key)
	took = time.Since(start)
	if err != nil {
		return nil, took, &ResolveError{Host: t.host, Err: err}
	}

	seen := make(map[netip.Addr]struct{}, len(found))
	for _, a := range found {
		a = a.Unmap()
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, took, &ResolveError{Host: t.host, Err: errNoAddresses}
	}
	return addrs, took, nil
}

func (r *run) failTarget(t target, took time.Duration, err error) {
	for _, sp := range r.ports.spans {
		for p := sp.lo; p <= sp.hi; p++ {
			if r.ctx.Err() != nil {
				return
			}
			r.emit(Result{
				Host:     t.host,
				Port:     uint16(p),
				State:    StateError,
				Duration: took,
				Err:      err,
			})
		}
	}
}

func (r *run) probe(host string, addr netip.Addr, port uint16) {
	if r.ctx.Err() != nil {
		return
	}

	res := Result{Host: host, IP: net.IP(addr.AsSlice()), Port: port}

	start := time.Now()
	conn, err := r.dial(addr, port)
	res.Duration = time.Since(start)

	if err == nil {
		res.State = StateOpen
		closeConn(conn)
	} else {
		res.State = classify(r.ctx, err)
		res.Err = err
	}
	r.emit(res)
}

func (r *run) dial(addr netip.Addr, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(r.ctx, r.cfg.connectTimeout)
	defer cancel()
	return r.cfg.dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
}

func (r *run) emit(res Result) {
	select {
	case r.out <- res:
		return
	case <-r.ctx.Done():
	}

	t := time.NewTimer(r.cfg.cancelGrace)
	defer t.Stop()
	select {
	case r.out <- res:
	case <-t.C:
	}
}

func closeConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}
