package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

func classify(scanCtx context.Context, err error) State {
	switch {
	case isErrno(err, refusedErrnos):
		return StateClosed
	case isErrno(err, unreachableErrnos):
		return StateUnreachable
	case scanCtx.Err() != nil, errors.Is(err, context.Canceled):
		return StateCanceled
	case isTimeout(err):
		return StateTimeout
	default:
		return StateError
	}
}

func isErrno(err error, codes []syscall.Errno) bool {
	for _, c := range codes {
		if errors.Is(err, c) {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
