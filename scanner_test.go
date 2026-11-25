package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ---- test doubles ----------------------------------------------------------

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type resolveFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolveFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

// countingConn is a net.Conn whose only working method is Close.
type countingConn struct {
	net.Conn
	closed *atomic.Int64
}

func (c countingConn) Close() error {
	c.closed.Add(1)
	return nil
}

// portOf extracts the port from "host:port".
func portOf(t testing.TB, address string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("bad address %q: %v", address, err)
	}
	n, err := net.LookupPort("tcp", p)
	if err != nil {
		t.Fatalf("bad port in %q: %v", address, err)
	}
	return n
}

// blockUntilDone is a dialer that hangs until its context is done.
func blockUntilDone(calls *atomic.Int64) dialFunc {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		if calls != nil {
			calls.Add(1)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

func mustNew(t testing.TB, opts ...Option) *Scanner {
	t.Helper()
	s, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func mustScan(t testing.TB, s *Scanner, ctx context.Context, hosts []string, ports Ports) <-chan Result {
	t.Helper()
	ch, err := s.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return ch
}

func collect(ch <-chan Result) []Result {
	var all []Result
	for r := range ch {
		all = append(all, r)
	}
	return all
}

// waitClosed fails the test if ch is not closed (after draining) in time.
func waitClosed(t testing.TB, ch <-chan Result, d time.Duration) []Result {
	t.Helper()
	done := make(chan []Result, 1)
	go func() { done <- collect(ch) }()
	select {
	case all := <-done:
		return all
	case <-time.After(d):
		t.Fatal("results channel was not closed in time")
		return nil
	}
}

func listen(t testing.TB, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// freePort returns a port nobody listens on.
func freePort(t testing.TB) int {
	t.Helper()
	ln := listen(t, "tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// ---- tests with real sockets ----------------------------------------------

func TestScanRealSockets(t *testing.T) {
	ln := listen(t, "tcp", "127.0.0.1:0")
	openPort := ln.Addr().(*net.TCPAddr).Port
	closedPort := freePort(t)

	s := mustNew(t, WithConnectTimeout(2*time.Second))
	results := waitClosed(t, mustScan(t, s, context.Background(),
		[]string{"127.0.0.1"}, List(openPort, closedPort)), 10*time.Second)

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(results), results)
	}
	byPort := map[uint16]Result{}
	for _, r := range results {
		byPort[r.Port] = r
		if r.Host != "127.0.0.1" || !r.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Errorf("bad host/IP: %+v", r)
		}
		if r.Duration <= 0 {
			t.Errorf("duration not set: %+v", r)
		}
	}
	if r := byPort[uint16(openPort)]; r.State != StateOpen || r.Err != nil {
		t.Errorf("open port: %+v", r)
	}
	if r := byPort[uint16(closedPort)]; r.State != StateClosed || r.Err == nil {
		t.Errorf("closed port: %+v", r)
	}
}

func TestScanIPv6Loopback(t *testing.T) {
	ln := listen(t, "tcp6", "[::1]:0")
	port := ln.Addr().(*net.TCPAddr).Port

	s := mustNew(t)
	results := waitClosed(t, mustScan(t, s, context.Background(), []string{"::1"}, List(port)), 10*time.Second)
	if len(results) != 1 || results[0].State != StateOpen || !results[0].IP.Equal(net.IPv6loopback) {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestZeroValueScannerIsUsable(t *testing.T) {
	ln := listen(t, "tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port

	var s Scanner
	results := waitClosed(t, mustScan(t, &s, context.Background(), []string{"127.0.0.1"}, List(port)), 10*time.Second)
	if len(results) != 1 || results[0].State != StateOpen {
		t.Fatalf("unexpected results: %+v", results)
	}
}

// ---- tests with fakes ------------------------------------------------------

func TestStates(t *testing.T) {
	var closed atomic.Int64
	dialer := dialFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		switch portOf(t, address) {
		case 1:
			return nil, opErr(syscall.ECONNREFUSED)
		case 2:
			<-ctx.Done() // never answers: the connect timeout must fire
			return nil, ctx.Err()
		case 3:
			return nil, opErr(syscall.ENETUNREACH)
		case 4:
			return nil, errors.New("boom")
		default:
			return countingConn{closed: &closed}, nil
		}
	})
	s := mustNew(t, WithDialer(dialer), WithConnectTimeout(30*time.Millisecond))

	results := waitClosed(t, mustScan(t, s, context.Background(), []string{"192.0.2.1"}, Range(1, 5)), 5*time.Second)

	got := map[uint16]State{}
	errs := map[uint16]error{}
	for _, r := range results {
		got[r.Port] = r.State
		errs[r.Port] = r.Err
	}
	want := map[uint16]State{1: StateClosed, 2: StateTimeout, 3: StateUnreachable, 4: StateError, 5: StateOpen}
	for port, w := range want {
		if got[port] != w {
			t.Errorf("port %d: state %v, want %v", port, got[port], w)
		}
	}
	if !errors.Is(errs[1], syscall.ECONNREFUSED) {
		t.Errorf("closed: Err should wrap ECONNREFUSED, got %v", errs[1])
	}
	if !errors.Is(errs[2], context.DeadlineExceeded) {
		t.Errorf("timeout: Err should wrap DeadlineExceeded, got %v", errs[2])
	}
	if errs[5] != nil {
		t.Errorf("open: Err = %v, want nil", errs[5])
	}
	if n := closed.Load(); n != 1 {
		t.Errorf("open connection closed %d times, want 1", n)
	}
}

func TestAllOpenConnectionsAreClosed(t *testing.T) {
	var opened, closed atomic.Int64
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		opened.Add(1)
		return countingConn{closed: &closed}, nil
	})
	s := mustNew(t, WithDialer(dialer), WithConcurrency(16))
	results := waitClosed(t, mustScan(t, s, context.Background(), []string{"192.0.2.1", "192.0.2.2"}, Range(1, 500)), 10*time.Second)

	if len(results) != 1000 || opened.Load() != 1000 || closed.Load() != 1000 {
		t.Fatalf("results=%d opened=%d closed=%d, want 1000 each", len(results), opened.Load(), closed.Load())
	}
}

func TestDNSNameWithSeveralAddresses(t *testing.T) {
	resolver := resolveFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "multi.example" {
			t.Errorf("unexpected lookup: %s %s", network, host)
		}
		return []netip.Addr{
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("::ffff:192.0.2.1"), // duplicate of the first one
		}, nil
	})
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		return countingConn{closed: new(atomic.Int64)}, nil
	})
	s := mustNew(t, WithResolver(resolver), WithDialer(dialer))

	results := waitClosed(t, mustScan(t, s, context.Background(), []string{"Multi.Example"}, List(80, 443)), 5*time.Second)
	if len(results) != 4 {
		t.Fatalf("got %d results, want 4 (2 addresses x 2 ports): %+v", len(results), results)
	}
	ips := map[string]int{}
	for _, r := range results {
		if r.Host != "Multi.Example" || r.State != StateOpen {
			t.Errorf("unexpected result %+v", r)
		}
		ips[r.IP.String()]++
	}
	if ips["192.0.2.1"] != 2 || ips["2001:db8::1"] != 2 {
		t.Errorf("addresses: %v", ips)
	}
}

func TestUnresolvableNameDoesNotStopTheScan(t *testing.T) {
	resolver := resolveFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "nope.invalid":
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		case "empty.example":
			return nil, nil
		}
		t.Errorf("unexpected lookup of %q", host)
		return nil, errors.New("unexpected")
	})
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		return countingConn{closed: new(atomic.Int64)}, nil
	})
	s := mustNew(t, WithResolver(resolver), WithDialer(dialer))

	results := waitClosed(t, mustScan(t, s, context.Background(),
		[]string{"nope.invalid", "127.0.0.1", "empty.example"}, List(1, 2, 3)), 5*time.Second)

	var failed, open int
	for _, r := range results {
		switch r.Host {
		case "nope.invalid", "empty.example":
			failed++
			var re *ResolveError
			if r.State != StateError || r.IP != nil || !errors.As(r.Err, &re) || re.Host != r.Host {
				t.Errorf("bad resolution failure result: %+v", r)
			}
			if r.Host == "nope.invalid" {
				var dnsErr *net.DNSError
				if !errors.As(r.Err, &dnsErr) || !dnsErr.IsNotFound {
					t.Errorf("DNS error must be reachable through errors.As: %v", r.Err)
				}
			}
		case "127.0.0.1":
			open++
			if r.State != StateOpen {
				t.Errorf("unexpected %+v", r)
			}
		}
	}
	if failed != 6 || open != 3 {
		t.Fatalf("failed=%d open=%d, want 6 and 3", failed, open)
	}
}

func TestDuplicatesAreScannedOnce(t *testing.T) {
	var lookups atomic.Int64
	resolver := resolveFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
	})
	var dials atomic.Int64
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return countingConn{closed: new(atomic.Int64)}, nil
	})
	s := mustNew(t, WithResolver(resolver), WithDialer(dialer))

	hosts := []string{
		"a.example", "A.EXAMPLE.", // same name
		"198.51.100.7", "198.51.100.7", // same literal, also the address of a.example
		"b.example", // another name for the same address
	}
	results := waitClosed(t, mustScan(t, s, context.Background(), hosts, List(80, 80, 443)), 5*time.Second)

	if len(results) != 2 || dials.Load() != 2 {
		t.Fatalf("results=%d dials=%d, want 2 each: %+v", len(results), dials.Load(), results)
	}
	for _, r := range results {
		if r.Host != "a.example" {
			t.Errorf("result should carry the first name that produced the address, got %q", r.Host)
		}
	}
	if lookups.Load() != 2 { // a.example and b.example; the repeated name is skipped
		t.Errorf("lookups = %d, want 2", lookups.Load())
	}
}

func TestConcurrencyLimit(t *testing.T) {
	const limit = 7
	var inFlight, maxInFlight atomic.Int64
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		n := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond)
		inFlight.Add(-1)
		return countingConn{closed: new(atomic.Int64)}, nil
	})
	s := mustNew(t, WithDialer(dialer), WithConcurrency(limit))

	results := waitClosed(t, mustScan(t, s, context.Background(), []string{"192.0.2.1", "192.0.2.2"}, Range(1, 200)), 20*time.Second)
	if len(results) != 400 {
		t.Fatalf("got %d results, want 400", len(results))
	}
	if m := maxInFlight.Load(); m > limit || m < 2 {
		t.Fatalf("max in flight = %d, want 2..%d", m, limit)
	}
}

func TestSlowConsumerBackpressure(t *testing.T) {
	var dials atomic.Int64
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return countingConn{closed: new(atomic.Int64)}, nil
	})
	const limit = 4
	s := mustNew(t, WithDialer(dialer), WithConcurrency(limit))

	ch := mustScan(t, s, context.Background(), []string{"192.0.2.1"}, Range(1, 5000))

	// Nobody reads: every worker is parked on its undelivered result, so the
	// producer cannot start anything new.
	time.Sleep(150 * time.Millisecond)
	if n := dials.Load(); n != limit {
		t.Fatalf("dials without a reader = %d, want exactly %d", n, limit)
	}

	if all := waitClosed(t, ch, 20*time.Second); len(all) != 5000 {
		t.Fatalf("got %d results after draining, want 5000", len(all))
	}
}

func TestCancelStopsNewJobsAndClosesChannel(t *testing.T) {
	var calls atomic.Int64
	const limit = 4
	s := mustNew(t, WithDialer(blockUntilDone(&calls)), WithConcurrency(limit), WithConnectTimeout(time.Minute))
	s.cfg.cancelGrace = time.Second // the reader below is active, so this is only an upper bound

	ctx, cancel := context.WithCancel(context.Background())
	ch := mustScan(t, s, ctx, []string{"192.0.2.1"}, Range(1, 1000))

	done := make(chan []Result, 1)
	go func() { done <- collect(ch) }()

	// Wait until all workers are blocked in the dialer.
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < limit && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()

	var results []Result
	select {
	case results = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed after cancel")
	}

	if n := calls.Load(); n != limit {
		t.Errorf("dials = %d, want %d: new jobs were started after cancel", n, limit)
	}
	if len(results) != limit {
		t.Errorf("got %d results, want %d canceled ones", len(results), limit)
	}
	for _, r := range results {
		if r.State != StateCanceled || !errors.Is(r.Err, context.Canceled) {
			t.Errorf("unexpected result after cancel: %+v", r)
		}
	}
}

func TestContextDeadlineIsReportedAsCanceled(t *testing.T) {
	s := mustNew(t, WithDialer(blockUntilDone(nil)), WithConcurrency(2), WithConnectTimeout(time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	results := waitClosed(t, mustScan(t, s, ctx, []string{"192.0.2.1"}, Range(1, 100)), 5*time.Second)
	if len(results) == 0 || len(results) > 2 {
		t.Fatalf("got %d results, want 1..2", len(results))
	}
	for _, r := range results {
		if r.State != StateCanceled {
			t.Errorf("state = %v, want canceled (the scan deadline, not connect timeout)", r.State)
		}
	}
}

func TestCancelDuringSlowResolve(t *testing.T) {
	resolver := resolveFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	s := mustNew(t, WithResolver(resolver), WithResolveTimeout(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	ch := mustScan(t, s, ctx, []string{"slow.example", "slow2.example"}, Range(1, 1000))
	time.AfterFunc(20*time.Millisecond, cancel)

	if results := waitClosed(t, ch, 5*time.Second); len(results) != 0 {
		t.Fatalf("a canceled resolution must not produce results, got %d", len(results))
	}
}

func TestResolveTimeout(t *testing.T) {
	resolver := resolveFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	s := mustNew(t, WithResolver(resolver), WithResolveTimeout(20*time.Millisecond))
	results := waitClosed(t, mustScan(t, s, context.Background(), []string{"slow.example"}, List(1, 2)), 5*time.Second)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		var re *ResolveError
		if r.State != StateError || !errors.As(r.Err, &re) || !errors.Is(r.Err, context.DeadlineExceeded) {
			t.Errorf("bad result: %+v", r)
		}
	}
}

func TestNoGoroutineLeakWhenConsumerGivesUp(t *testing.T) {
	before := runtime.NumGoroutine()

	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		return countingConn{closed: new(atomic.Int64)}, nil
	})
	s := mustNew(t, WithDialer(dialer), WithConcurrency(8))
	s.cfg.cancelGrace = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	ch := mustScan(t, s, ctx, []string{"192.0.2.1"}, Range(1, 5000))
	<-ch // read one result, then walk away
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines: before=%d after=%d", before, after)
	}
}

func TestScannerReuseAndParallelScans(t *testing.T) {
	ln := listen(t, "tcp", "127.0.0.1:0")
	openPort := ln.Addr().(*net.TCPAddr).Port
	closedPort := freePort(t)
	s := mustNew(t, WithConcurrency(4), WithConnectTimeout(2*time.Second))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, List(openPort, closedPort))
				if err != nil {
					t.Error(err)
					return
				}
				got := map[uint16]State{}
				for r := range ch {
					got[r.Port] = r.State
				}
				if got[uint16(openPort)] != StateOpen || got[uint16(closedPort)] != StateClosed || len(got) != 2 {
					t.Errorf("bad results: %v", got)
				}
			}
		}()
	}
	wg.Wait()
}

func TestResultsHaveIndependentIPSlices(t *testing.T) {
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		return countingConn{closed: new(atomic.Int64)}, nil
	})
	s := mustNew(t, WithDialer(dialer))
	results := waitClosed(t, mustScan(t, s, context.Background(), []string{"192.0.2.1"}, List(1, 2)), 5*time.Second)
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	results[0].IP[len(results[0].IP)-1] = 99
	if results[1].IP.String() != "192.0.2.1" {
		t.Fatalf("IP slices are shared between results: %v", results[1].IP)
	}
}

// ---- validation ------------------------------------------------------------

func TestScanValidation(t *testing.T) {
	s := mustNew(t, WithDialer(dialFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Error("nothing must be dialed when validation fails")
		return nil, errors.New("unexpected")
	})))
	ctx := context.Background()

	tests := []struct {
		name  string
		hosts []string
		ports Ports
		want  []error
	}{
		{"no hosts", nil, Range(1, 10), []error{ErrNoHosts}},
		{"empty host", []string{""}, Range(1, 10), []error{ErrEmptyHost}},
		{"invalid host", []string{"1.2.3"}, Range(1, 10), []error{ErrInvalidHost}},
		{"no ports", []string{"127.0.0.1"}, Ports{}, []error{ErrNoPorts}},
		{"empty list", []string{"127.0.0.1"}, List(), []error{ErrNoPorts}},
		{"port 0", []string{"127.0.0.1"}, List(0), []error{ErrInvalidPort}},
		{"port too big", []string{"127.0.0.1"}, Range(1, 65536), []error{ErrInvalidPort}},
		{"reversed range", []string{"127.0.0.1"}, Range(1000, 1), []error{ErrInvalidRange}},
		{"everything wrong", []string{"", "x y"}, Range(2, 1), []error{ErrEmptyHost, ErrInvalidHost, ErrInvalidRange}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := s.Scan(ctx, tt.hosts, tt.ports)
			if ch != nil {
				t.Error("channel must be nil on error")
			}
			for _, want := range tt.want {
				if !errors.Is(err, want) {
					t.Errorf("err = %v, want it to match %v", err, want)
				}
			}
		})
	}
}

func TestScanRejectsBadContext(t *testing.T) {
	s := mustNew(t)

	var nilCtx context.Context
	if ch, err := s.Scan(nilCtx, []string{"127.0.0.1"}, List(80)); err == nil || ch != nil {
		t.Errorf("nil context: ch=%v err=%v", ch, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, List(80))
	if !errors.Is(err, context.Canceled) || ch != nil {
		t.Errorf("canceled context: ch=%v err=%v", ch, err)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	bad := []Option{
		WithConcurrency(0), WithConcurrency(-5),
		WithConnectTimeout(0), WithConnectTimeout(-time.Second),
		WithResolveTimeout(0),
		WithDialer(nil), WithResolver(nil),
	}
	for i, opt := range bad {
		if _, err := New(opt); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("option #%d: err = %v, want ErrInvalidOption", i, err)
		}
	}
	if _, err := New(nil, WithConcurrency(1)); err != nil {
		t.Errorf("nil option must be ignored, got %v", err)
	}
}
