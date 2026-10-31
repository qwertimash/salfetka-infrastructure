package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClockRecoveryRetriesOnlyClosedAttemptsAndRemainsCancellable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls, reports := 0, 0
	closed := true
	err := supervise(ctx, func(context.Context) error {
		if !closed {
			t.Fatal("overlapping attempts")
		}
		closed = false
		defer func() { closed = true }()
		calls++
		if calls < 3 {
			return errors.New("vpn_engine_clock_untrusted")
		}
		return errors.New("vpn_signature_invalid")
	}, time.Millisecond, func() { reports++ })
	if err == nil || err.Error() != "vpn_signature_invalid" || calls != 3 || reports != 2 {
		t.Fatal("recovery classification")
	}
	started := time.Now()
	err = supervise(ctx, func(context.Context) error { return errors.New("node_clock_untrusted") }, time.Hour, cancel)
	if err != nil || time.Since(started) > time.Second {
		t.Fatal("shutdown blocked by recovery wait")
	}
	for _, code := range []string{"vpn_storage_failed", "vpn_generation_conflict", "node_authorization_rejected", "vpn_engine_grant_failed", "untrusted payload"} {
		if recoverableClock(errors.New(code)) {
			t.Fatal("non-clock failure retried")
		}
	}
}
