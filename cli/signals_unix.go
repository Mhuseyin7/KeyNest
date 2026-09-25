//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// forwardSignals keeps cancellation semantics consistent for Unix child processes.
func forwardSignals(process *os.Process) func() {
	input := make(chan os.Signal, 2)
	done := make(chan struct{})
	signal.Notify(input, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for {
			select {
			case received := <-input:
				_ = process.Signal(received)
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(input); close(done) }
}
