package portscan

import (
	"net"
	"time"
)

// describes the outcome of checking one port of one address.
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	// The underlying error for every state except StateOpen, where it is nil.
	Err error
}
