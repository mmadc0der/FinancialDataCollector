package kernel

import (
    "testing"
)

func TestPrefixed(t *testing.T) {
    if prefixed("", "k") != "k" { t.Fatalf("no prefix case failed") }
    if prefixed("fdc:", "events") != "fdc:events" { t.Fatalf("prefix case failed") }
}

// Removed redundant envelope adapter tests and helpers


