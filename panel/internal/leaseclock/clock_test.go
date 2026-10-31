package leaseclock

import (
	"testing"
	"time"
)

func TestCorrectionsNeverStopOrReverseElapsedTime(t *testing.T) {
	base, mono := time.Unix(1000, 0), time.Now()
	c := New(base, mono)
	for i := 1; i <= 100; i++ {
		d := time.Duration(i) * 50 * time.Millisecond
		wall, ok := c.Observe(base.Add(d-300*time.Millisecond), mono.Add(d))
		if !ok || !wall.Equal(base.Add(d)) {
			t.Fatalf("correction extended deadline at sample %d", i)
		}
	}
}

func TestRepeatedSmallStepsExhaustOneCumulativeBudget(t *testing.T) {
	base, mono := time.Unix(1000, 0), time.Now()
	c := New(base, mono)
	for i := 1; i <= 4; i++ {
		d := time.Duration(i) * time.Second
		_, ok := c.Observe(base.Add(d-time.Duration(i)*300*time.Millisecond), mono.Add(d))
		if ok != (i < 4) {
			t.Fatalf("cumulative rollback at step %d trusted=%t", i, ok)
		}
	}
	if _, ok := c.Observe(base.Add(time.Hour), mono.Add(time.Hour)); ok {
		t.Fatal("restoring wall clock cleared a poisoned clock")
	}
}

func TestForwardJumpBoundaryAndMonotonicRollback(t *testing.T) {
	base, mono := time.Unix(1000, 0), time.Now()
	c := New(base, mono)
	forward := base.Add(time.Hour)
	if wall, ok := c.Observe(forward, mono.Add(time.Second)); !ok || !wall.Equal(forward) {
		t.Fatal("forward clock jump did not advance expiry")
	}
	if _, ok := c.Observe(forward, mono.Add(2*time.Second)); !ok {
		t.Fatal("exact one-second correction rejected")
	}
	if _, ok := c.Observe(forward, mono.Add(2*time.Second+time.Nanosecond)); ok {
		t.Fatal("correction outside budget accepted")
	}
	c = New(base, mono)
	if _, ok := c.Observe(base, mono.Add(-time.Nanosecond)); ok {
		t.Fatal("monotonic clock reversed")
	}
}
