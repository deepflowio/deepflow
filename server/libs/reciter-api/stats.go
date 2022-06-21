package reciter_api

import (
	"fmt"
	"strings"
	"time"
)

type QueryStatsItem struct {
	Processed uint64        `json:"processed"`
	StartTime time.Duration `json:"start_time"`
	EndTime   time.Duration `json:"end_time"`
}

func (it *QueryStatsItem) Elapsed() time.Duration {
	return it.EndTime - it.StartTime
}

func (it *QueryStatsItem) String() string {
	return fmt.Sprintf("processed %d in %v", it.Processed, it.Elapsed())
}

type QueryStatsItems []QueryStatsItem

func (it QueryStatsItems) Elapsed() time.Duration {
	items := []QueryStatsItem(it)
	if len(items) == 0 {
		return 0
	}
	startTime := items[0].StartTime
	endTime := items[0].EndTime
	for _, item := range items[1:] {
		if item.StartTime < startTime {
			startTime = item.StartTime
		}
		if item.EndTime > endTime {
			endTime = item.EndTime
		}
	}
	return endTime - startTime
}

func (it QueryStatsItems) String() string {
	items := []QueryStatsItem(it)
	if len(items) == 0 {
		return "n/a"
	}
	processed := items[0].Processed
	startTime := items[0].StartTime
	endTime := items[0].EndTime
	for _, item := range items[1:] {
		processed = processed + item.Processed
		if item.StartTime < startTime {
			startTime = item.StartTime
		}
		if item.EndTime > endTime {
			endTime = item.EndTime
		}
	}
	return fmt.Sprintf("processed %d in %v", processed, endTime-startTime)
}

type QueryStats struct {
	Total         QueryStatsItem   `json:"total"`
	InfluxDB      QueryStatsItem   `json:"influx_db"`
	Mapper        []QueryStatsItem `json:"mapper"`
	Reducer       []QueryStatsItem `json:"reducer"`
	Exchange      QueryStatsItem   `json:"exchange"`
	GlobalReducer []QueryStatsItem `json:"global_reducer"`
	Sorter        QueryStatsItem   `json:"sorter"`
}

func (s *QueryStats) String() string {
	items := []string{
		fmt.Sprintf("Total: %s", s.Total.String()),
		fmt.Sprintf("InfluxDB: %s", s.InfluxDB.String()),
		fmt.Sprintf("Mapper: %s", QueryStatsItems.String(s.Mapper)),
		fmt.Sprintf("Reducer: %s", QueryStatsItems.String(s.Reducer)),
		fmt.Sprintf("Exchange: %s", s.Exchange.String()),
		fmt.Sprintf("GlobalReducer: %s", QueryStatsItems.String(s.GlobalReducer)),
		fmt.Sprintf("Sorter: %s", s.Sorter.String()),
	}
	return strings.Join(items, ", ")
}
