/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
