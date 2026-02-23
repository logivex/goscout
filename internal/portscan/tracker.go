package portscan

import "sync"

type Tracker struct {
	mu        sync.Mutex
	responded map[int]bool
	seen      map[int]bool
	results   []Result
}

func NewTracker() *Tracker {
	return &Tracker{
		responded: make(map[int]bool),
		seen:      make(map[int]bool),
	}
}

func (t *Tracker) Run() {}

// Add records a port result, ignoring duplicates.
func (t *Tracker) Add(r Result) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.responded[r.Port] = true
	if t.seen[r.Port] {
		return
	}
	t.seen[r.Port] = true
	if r.State == StateOpen || r.State == StateClosed {
		t.results = append(t.results, r)
	}
}

// Results returns all recorded open/closed results without filtering.
func (t *Tracker) Results() []Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Result, len(t.results))
	copy(out, t.results)
	return out
}

// Close finalises results and marks unresponded ports as filtered.
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
