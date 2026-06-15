package testutil

import "sync/atomic"

// FakeClock is a deterministic model.Clock for tests. NowNS returns the
// current nanosecond value; Set/Advance drive it deterministically.
type FakeClock struct {
	nowNS atomic.Int64
}

// NewFakeClock creates a FakeClock starting at startNS.
func NewFakeClock(startNS int64) *FakeClock {
	c := &FakeClock{}
	c.nowNS.Store(startNS)
	return c
}

// NowNS implements model.Clock.
func (c *FakeClock) NowNS() int64 { return c.nowNS.Load() }

// Set replaces the current time.
func (c *FakeClock) Set(ns int64) { c.nowNS.Store(ns) }

// Advance adds deltaNS to the current time.
func (c *FakeClock) Advance(deltaNS int64) { c.nowNS.Add(deltaNS) }
