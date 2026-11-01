package leaseclock

import (
	"testing"
	"time"
)

func TestRestartWaitsForActualWallWithoutLoweringWatermark(t *testing.T) {
	watermark := time.Now().UTC().Add(150 * time.Millisecond)
	now, ok := AwaitRestart(watermark)
	if !ok || now.Before(watermark) || time.Now().Before(watermark) {
		t.Fatal("restart authorized before actual wall reached watermark")
	}
}

func TestRestartRejectsLargeClockReversal(t *testing.T) {
	if _, ok := AwaitRestart(time.Now().UTC().Add(2 * MaxCorrection)); ok {
		t.Fatal("large clock reversal accepted")
	}
}
