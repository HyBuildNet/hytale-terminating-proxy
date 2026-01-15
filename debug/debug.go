package debug

import (
	"log"
	"sync/atomic"
)

var enabled atomic.Bool

// IsEnabled returns whether debug mode is active.
func IsEnabled() bool { return enabled.Load() }

// SetEnabled enables or disables debug mode.
func SetEnabled(v bool) { enabled.Store(v) }

// Printf logs a formatted message if debug mode is enabled.
func Printf(format string, args ...any) {
	if enabled.Load() {
		log.Printf(format, args...)
	}
}
