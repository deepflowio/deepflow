package common

import (
	"fmt"
	"time"
)

const (
	ZERO       Interval = 0
	ONE_MINUTE          = 60 * Interval(time.Second)
	ONE_HOUR            = 60 * ONE_MINUTE
	ONE_DAY             = 24 * ONE_HOUR
	ONE_WEEK            = 7 * ONE_DAY
	ONE_QWEEK           = 4 * ONE_WEEK
	ONE_MONTH           = 30 * ONE_DAY
	ONE_YEAR            = 365 * ONE_DAY
	INFINITE            = 1 << 30 * Interval(time.Second)
)

var intervalText = map[Interval]string{
	ZERO:       "0",
	ONE_MINUTE: "1m",
	ONE_HOUR:   "1h",
	ONE_DAY:    "1d",
	ONE_WEEK:   "1w",
	ONE_QWEEK:  "4w",
	ONE_MONTH:  "30d",
	ONE_YEAR:   "365d",
	INFINITE:   "34y",
}

type Interval time.Duration

func (itv Interval) GetAppIndex(appName string) string {
	return fmt.Sprintf("%s__%s_*", appName, itv.String())
}

func (itv Interval) AlignTimestamp(timestamp time.Duration) time.Duration {
	_, zoneOffset := time.Now().Zone()
	timestamp += time.Duration(zoneOffset) * time.Second
	return timestamp/time.Duration(itv)*time.Duration(itv) - time.Duration(zoneOffset)*time.Second
}

func (itv Interval) String() string {
	return intervalText[itv]
}
