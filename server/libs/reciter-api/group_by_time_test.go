/*
 * Copyright (c) 2022 Yunshan Networks
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
	"testing"
	"time"
)

func TestGroupByTimeSimple(t *testing.T) {
	pMinute := GroupByTime{
		Step:                Duration(time.Minute),
		StepInSeconds:       int32(time.Minute / time.Second),
		WindowSize:          Duration(time.Minute),
		WindowSizeInSeconds: int32(time.Minute / time.Second),
	}
	if start, end := pMinute.GetEffectiveTimestampRange(128); start != 120 || end != start {
		t.Error("时间计算不正确")
	}

	pBeijingDay := GroupByTime{
		Step:                Duration(24 * time.Hour),
		StepInSeconds:       int32(24 * time.Hour / time.Second),
		WindowSize:          Duration(24 * time.Hour),
		WindowSizeInSeconds: int32(24 * time.Hour / time.Second),
		Offset:              Duration(8 * time.Hour),
		OffsetInSeconds:     int32(8 * time.Hour / time.Second),
	}
	startOfDay := 31*24*time.Hour - 8*time.Hour
	if start, end := pBeijingDay.GetEffectiveTimestampRange(uint32((startOfDay + 5*time.Minute) / time.Second)); start != uint32(startOfDay/time.Second) || end != start {
		t.Error("时间计算不正确")
	}
	if start, end := pBeijingDay.GetEffectiveTimestampRange(uint32((startOfDay - 5*time.Minute) / time.Second)); start != uint32((startOfDay-24*time.Hour)/time.Second) || end != start {
		t.Error("时间计算不正确")
	}

	pSlide := GroupByTime{
		Step:                Duration(10 * time.Second),
		StepInSeconds:       int32(10 * time.Second / time.Second),
		WindowSize:          Duration(time.Minute),
		WindowSizeInSeconds: int32(time.Minute / time.Second),
	}
	if start, end := pSlide.GetEffectiveTimestampRange(55); start != 60 || end != 110 {
		t.Error("时间计算不正确")
	}
	if start, end := pSlide.GetEffectiveTimestampRange(60); start != 60 || end != 110 {
		t.Error("时间计算不正确")
	}
	pSlideMinute := GroupByTime{
		Step:                Duration(time.Minute),
		StepInSeconds:       int32(time.Minute / time.Second),
		WindowSize:          Duration(2 * time.Minute),
		WindowSizeInSeconds: int32(2 * time.Minute / time.Second),
	}
	for i := uint32(1597310333); i < 1597310500; i++ {
		start, end := pSlideMinute.GetEffectiveTimestampRange(i)
		if start-uint32(pSlideMinute.WindowSizeInSeconds) >= i || start < i {
			t.Error("滑窗计算错误")
		}
		if end-uint32(pSlideMinute.WindowSizeInSeconds) >= i || end < i {
			t.Error("滑窗计算错误")
		}
	}
}
