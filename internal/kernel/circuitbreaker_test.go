package kernel

import (
	"testing"
	"time"
)

func TestCircuitBreakerTransitions(t *testing.T) {
	cb := newCircuitBreaker(1, 10*time.Millisecond)

	if !cb.canExecute() {
		t.Fatalf("expected canExecute true in closed state")
	}

	// trigger open
	cb.onFailure()
	if cb.canExecute() {
		t.Fatalf("expected canExecute false in open state before timeout")
	}

	// wait for half-open window
	time.Sleep(15 * time.Millisecond)
	if !cb.canExecute() {
		t.Fatalf("expected canExecute true in half-open state after timeout")
	}

	// success should close the breaker
	cb.onSuccess()
	if !cb.canExecute() {
		t.Fatalf("expected canExecute true after success (closed)")
	}
}
