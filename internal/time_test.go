package internal

import (
	"testing"
	"time"
)

func TestAwsTimeFromTime(t *testing.T) {
	t.Run("valid time", func(t *testing.T) {
		timeStr := AwsTimeFromTime(time.Date(2025, 06, 11, 8, 55, 0, 0, time.UTC))
		expected := "20250611T085500Z"
		if timeStr != expected {
			t.Errorf("expected %s but got %s", expected, timeStr)
		}
	})
}

func TestAwsTimeFromTimeShort(t *testing.T) {
	t.Run("valid time", func(t *testing.T) {
		timeStr := AwsTimeFromTimeShort(time.Date(2025, 06, 11, 8, 55, 0, 0, time.UTC))
		expected := "20250611"
		if timeStr != expected {
			t.Errorf("expected %s but got %s", expected, timeStr)
		}
	})
}
