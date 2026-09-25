//go:build windows

package main

import (
	"os"
	"os/signal"
)

// Windows exposes Ctrl+C as os.Interrupt and therefore needs no Unix constants.
func forwardSignals(process *os.Process) func() {
	input := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(input, os.Interrupt)
	go func() {
		select {
		case received := <-input:
			_ = process.Signal(received)
		case <-done:
		}
	}()
	return func() { signal.Stop(input); close(done) }
}
