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

package client

import (
	"github.com/deepflowio/deepflow/server/querier/common"
)

type Series struct {
	Values []interface{}
}

type SeriesArray []*Series

func SeriesEq(i *Series, j *Series, fieldIndex int, valueType string) bool {
	switch valueType {
	case VALUE_TYPE_INT:
		iValue := i.Values[fieldIndex].(int)
		jValue := j.Values[fieldIndex].(int)
		return SeriesValueEq(iValue, jValue)
	case VALUE_TYPE_STRING:
		iValue := i.Values[fieldIndex].(string)
		jValue := j.Values[fieldIndex].(string)
		return SeriesValueEq(iValue, jValue)
	case VALUE_TYPE_FLOAT64:
		iValue := i.Values[fieldIndex].(float64)
		jValue := j.Values[fieldIndex].(float64)
		return SeriesValueEq(iValue, jValue)
	}
	return true
}

type SeriesGroup struct {
	Series      SeriesArray
	GroupIndex  []int
	GroupValues []interface{}
	Schemas     common.ColumnSchemas
}

type SeriesSort struct {
	Series    SeriesArray
	SortIndex []int
	Reverse   []bool
	Schemas   common.ColumnSchemas
}

func (s *SeriesSort) Len() int {
	return len(s.Series)
}

func (s *SeriesSort) Swap(i, j int) {
	s.Series[i], s.Series[j] = s.Series[j], s.Series[i]
}

func (s *SeriesSort) Less(i, j int) bool {
	for index, sortIndex := range s.SortIndex {
		if SeriesEq(s.Series[i], s.Series[j], sortIndex, s.Schemas[sortIndex].ValueType) {
			continue
		}
		switch s.Schemas[sortIndex].ValueType {
		case VALUE_TYPE_INT:
			iValue := s.Series[i].Values[sortIndex].(int)
			jValue := s.Series[j].Values[sortIndex].(int)
			return SeriesValueLess(iValue, jValue, s.Reverse[index])
		case VALUE_TYPE_STRING:
			iValue := s.Series[i].Values[sortIndex].(string)
			jValue := s.Series[j].Values[sortIndex].(string)
			return SeriesValueLess(iValue, jValue, s.Reverse[index])
		case VALUE_TYPE_FLOAT64:
			iValue := s.Series[i].Values[sortIndex].(float64)
			jValue := s.Series[j].Values[sortIndex].(float64)
			return SeriesValueLess(iValue, jValue, s.Reverse[index])
		}
	}
	return false
}

func Group(seriesArray SeriesArray, groupIndex []int, schema common.ColumnSchemas) (groups []*SeriesGroup) {
	groups = []*SeriesGroup{}
	if len(groupIndex) == 0 {
		groups = append(groups, &SeriesGroup{
			Series: seriesArray,
		})
		return groups
	}

	if len(seriesArray) > 0 {
		groupValues := []interface{}{}
		for _, i := range groupIndex {
			groupValues = append(groupValues, seriesArray[0].Values[i])
		}
		groups = append(groups, &SeriesGroup{
			Series:      SeriesArray{seriesArray[0]},
			GroupIndex:  groupIndex,
			GroupValues: groupValues,
		})
	} else {
		return groups
	}
	nowSeries := seriesArray[0]
	nowGroup := groups[0]
	for _, series := range seriesArray[1:] {
		isEq := true
		for _, i := range groupIndex {
			if !SeriesEq(nowSeries, series, i, schema[i].ValueType) {
				isEq = false
				break
			}
		}
		if isEq {
			nowGroup.Series = append(nowGroup.Series, series)
		} else {
			nowSeries = series
			groupValues := []interface{}{}
			for _, i := range groupIndex {
				groupValues = append(groupValues, series.Values[i])
			}
			group := &SeriesGroup{
				Series:      SeriesArray{series},
				GroupIndex:  groupIndex,
				GroupValues: groupValues,
			}
			groups = append(groups, group)
			nowGroup = group
		}
	}
	return groups
}

func SeriesValueLess[T SeriersValueType](i T, j T, reverse bool) bool {
	if !reverse {
		return i < j
	} else {
		return i > j
	}
}

func SeriesValueEq[T SeriersValueType](i T, j T) bool {
	return i == j
}

type SeriersValueType interface {
	int | string | float64
}
