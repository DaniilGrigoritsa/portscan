//go:build !windows

package portscan

import "syscall"

var (
	refusedErrnos     = []syscall.Errno{syscall.ECONNREFUSED}
	unreachableErrnos = []syscall.Errno{
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		syscall.ENETDOWN,
		syscall.EHOSTDOWN,
	}
)
