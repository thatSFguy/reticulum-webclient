//go:build !windows

// SIGHUP-driven blocklist reload (Unix). Lets an operator update the
// blocklist file and `kill -HUP <pid>` without dropping live connections.

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func reloadSignals() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}
