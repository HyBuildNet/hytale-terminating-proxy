package debug

import (
	"fmt"
	"log"
	"sync/atomic"
)

var enabled atomic.Bool
var logChan = make(chan string, 10000)

func init() {
	go func() {
		for msg := range logChan {
			log.Print(msg)
		}
	}()
}

// IsEnabled returns whether debug mode is active.
func IsEnabled() bool { return enabled.Load() }

// SetEnabled enables or disables debug mode.
func SetEnabled(v bool) { enabled.Store(v) }

// Printf logs a formatted message if debug mode is enabled.
// Non-blocking - drops message if buffer is full.
func Printf(format string, args ...any) {
	if !enabled.Load() {
		return
	}
	select {
	case logChan <- fmt.Sprintf(format, args...):
	default:
		// Buffer voll - droppen statt blockieren
	}
}
