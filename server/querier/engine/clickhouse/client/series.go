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
	"reflect"

	"github.com/deepflowio/deepflow/server/querier/common"
)

type Series struct {
	Values []interface{}
}

type SeriesArray []*Series

func SeriesEq(i *Series, j *Series, fieldIndex int, valueType string) bool {
	return reflect.DeepEqual(i.Values[fieldIndex], j.Values[fieldIndex])
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

	for _, series := range seriesArray[1:] {
		isEq := false
		for _, group := range groups {
			if isEq {
				break
			}
			for _, s := range group.Series {
				if isEq {
					break
				}
				for index, i := range groupIndex {
					if isEq {
						break
					}
					groupEq := SeriesEq(s, series, i, schema[i].ValueType)
					if !groupEq {
						break
					}
					// all group tag is equal
					if index == len(groupIndex)-1 {
						isEq = true
						group.Series = append(group.Series, series)
					}
				}
			}

		}

		if !isEq {
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
		}
	}
	return groups
}
