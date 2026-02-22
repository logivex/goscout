package portscan

import "sync"

// Tracker records scan results and tracks which ports have responded.
type Tracker struct {
	mu        sync.Mutex
	responded map[int]bool
	results   []Result
}

// NewTracker returns an initialized Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		responded: make(map[int]bool),
	}
}

// Run is a no-op placeholder for interface compatibility.
func (t *Tracker) Run() {}

// Add records a scan result. It is safe for concurrent use.
func (t *Tracker) Add(r Result) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.responded[r.Port] = true
	if r.State == StateOpen || r.State == StateClosed {
		t.results = append(t.results, r)
	}
}

// Close finalizes the scan and returns all results.
// Ports that did not respond are marked as filtered.
func (t *Tracker) Close(allPorts []int) []Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	final := make([]Result, 0, len(t.results))
	final = append(final, t.results...)
	for _, p := range allPorts {
		if !t.responded[p] {
			final = append(final, Result{Port: p, State: StateFiltered})
		}
	}
	return final
}
