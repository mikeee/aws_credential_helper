package internal

import "time"

func AwsTimeFromTime(time time.Time) string {
	return time.Format("20060102T150405Z")
}

func AwsTimeFromTimeShort(time time.Time) string {
	return time.Format("20060102")
}
