package nodeagent

import "time"

// Bounded clock protection: persisted wall time survives restart; the monotonic
// anchor detects rollback within this process (one-second scheduling tolerance).
// This is not a secure hardware clock or a lease on the already applied config.
func (a *Agent) clockTrusted(floor time.Time) bool {
	now := a.now().UTC()
	return !now.Before(floor) && !now.Before(a.anchorWall.Add(a.monotonic().Sub(a.anchorMono)).Add(-time.Second))
}

func laterWall(a, b time.Time) time.Time {
	if b.After(a) {
		return b.UTC()
	}
	return a
}
