// Package leaseclock tolerates bounded wall-clock synchronization without
// extending an authorization deadline. Callers serialize all access.
package leaseclock

import "time"

const MaxCorrection = time.Second

type Clock struct {
	wall time.Time
	mono time.Time
	bad  bool
}

func New(wall, monotonic time.Time) Clock {
	return Clock{wall: wall.UTC(), mono: monotonic}
}

// Observe returns conservative absolute time: at least the previous value plus
// monotonic elapsed time, or a newer wall time. Small corrections never reset
// this floor, so repeated backwards steps cannot extend leases indefinitely.
// A violation is sticky for the lifetime of this clock. Persisted restart
// watermarks must still be checked before constructing a new clock.
func (c *Clock) Observe(wall, monotonic time.Time) (time.Time, bool) {
	elapsed := monotonic.Sub(c.mono)
	floor := c.wall.Add(elapsed)
	wall = wall.UTC()
	if elapsed < 0 || wall.Before(floor.Add(-MaxCorrection)) {
		c.bad = true
	}
	if c.bad {
		return c.wall, false
	}
	if wall.Before(floor) {
		wall = floor
	}
	c.wall, c.mono = wall, monotonic
	return wall, true
}
