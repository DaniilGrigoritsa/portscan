package portscan

type State uint8

const (
	// TCP connection was established.
	StateOpen State = iota + 1
	// The connection was explicitly refused (RST).
	StateClosed
	// The connection was not established within the connect timeout.
	StateTimeout
	// The host or the network cannot be reached (no route, network down, ICMP unreachable).
	StateUnreachable
	// The check was interrupted because the context passed to Scan was canceled or its deadline expired.
	StateCanceled
	// StateError is any other failure: DNS resolution errors, local resource
	// exhaustion and so on.
	StateError
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

func (s State) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}
