package leaseclock

import "time"

// AwaitRestart waits for actual wall time to reach a persisted conservative
// watermark before any listener starts. It never lowers that watermark. Small
// synchronization corrections may leave it ahead at restart; larger reversals
// are rejected, and monotonic elapsed time bounds the wait.
func AwaitRestart(watermark time.Time) (time.Time, bool) {
	start := time.Now()
	now := start
	for now.Before(watermark) {
		gap := watermark.Sub(now)
		remaining := MaxCorrection - time.Since(start)
		if gap > MaxCorrection || remaining <= 0 {
			return now, false
		}
		time.Sleep(min(gap, remaining))
		now = time.Now()
	}
	return now, true
}
