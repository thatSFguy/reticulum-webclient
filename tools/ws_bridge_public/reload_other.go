//go:build windows

// Windows has no SIGHUP; return a channel that never fires so the reload
// goroutine simply idles. Update the blocklist by restarting the service.

package main

import "os"

func reloadSignals() <-chan os.Signal {
	return make(chan os.Signal)
}
