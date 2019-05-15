package doctime

import (
	"time"
)

const (
	SECONDS_IN_MINUTE = time.Minute / time.Second
)

func RoundToSecond(t time.Duration) uint32 {
	return uint32(t / time.Second)
}

func RoundToMinute(t time.Duration) uint32 {
	return uint32(t / time.Minute * SECONDS_IN_MINUTE)
}
