package common

import (
	"fmt"
	"time"
)

type RetentionPolicy struct {
	Interval   Interval
	SplitSize  Interval
	Slots      int
	AliveSlots int
	HotSlots   int
}

func (rp RetentionPolicy) getAppIndex(appName string) string {
	return rp.Interval.GetAppIndex(appName)
}

func (rp RetentionPolicy) GetAppIndex(appName string, timestamp time.Duration) string {
	return fmt.Sprintf(
		"%s__%s_%dx%s_%s",
		appName,
		rp.Interval.String(),
		int(rp.SplitSize.AlignTimestamp(timestamp).Seconds()/time.Duration(rp.SplitSize).Seconds())%rp.Slots,
		rp.SplitSize.String(),
		time.Unix(int64(rp.SplitSize.AlignTimestamp(timestamp).Seconds()), 0).Format("06010215"))
}

func (rp RetentionPolicy) GetAppIndexName(indexName string, timestamp time.Duration) string {
	return fmt.Sprintf(
		"%s__%s_%s_%s",
		indexName,
		rp.Interval.String(),
		"*",
		time.Unix(int64(rp.SplitSize.AlignTimestamp(timestamp).Seconds()), 0).Format("06010215"))
}

func (rp RetentionPolicy) GetAppExpiredIndices(appName string, timestamp time.Duration) []string {
	expiredIndices := make([]string, 0)
	for i := rp.Slots - rp.AliveSlots - 1; i > 0; i-- {
		expiredIndices = append(expiredIndices,
			fmt.Sprintf(
				"%s__%s_%dx%s_*",
				appName,
				rp.Interval,
				(int(rp.SplitSize.AlignTimestamp(timestamp))/int(rp.SplitSize)+i)%rp.Slots,
				rp.SplitSize))
	}
	return expiredIndices
}
