//go:build windows

package portscan

import "syscall"

const (
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

var (
	refusedErrnos     = []syscall.Errno{wsaECONNREFUSED, syscall.ECONNREFUSED}
	unreachableErrnos = []syscall.Errno{
		wsaENETUNREACH, wsaEHOSTUNREACH, wsaENETDOWN, wsaEHOSTDOWN,
		syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN, syscall.EHOSTDOWN,
	}
)
