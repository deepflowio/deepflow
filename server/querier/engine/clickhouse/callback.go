/*
 * Copyright (c) 2023 Yunshan Networks
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

package clickhouse

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/view"
)

var TIME_FILL_LIMIT_DEFAULT = 20

type Callback struct {
	Args     []interface{}
	Function func([]interface{}) func(*common.Result) error
	Column   string
}

func (c *Callback) Format(m *view.Model) {
	m.AddCallback(c.Column, c.Function(c.Args))
}

func TimeFill(args []interface{}) func(result *common.Result) error { // group by time时的补点
	return func(result *common.Result) error {
		if result.Values == nil || len(result.Values) == 0 {
			return nil
		}
		m := args[0].(*view.Model)
		seriesSort := &client.SeriesSort{
			Series:    []*client.Series{},
			SortIndex: []int{},
			Reverse:   []bool{},
			Schemas:   result.Schemas,
		}
		for _, value := range result.Values {
			seriesSort.Series = append(seriesSort.Series, &client.Series{Values: value.([]interface{})})
		}
		var timeFieldIndex int
		// get time field index
		for i, column := range result.Columns {
			if column.(string) == strings.Trim(m.Time.Alias, "`") {
				timeFieldIndex = i
				break
			}
		}
		reverse := false
		for _, node := range m.Orders.Orders {
			order := node.(*view.Order)
			if strings.Trim(order.SortBy, "`") == strings.Trim(m.Time.Alias, "`") {
				if order.OrderBy == "desc" {
					reverse = true
				}
				break
			}
		}
		for i, schema := range result.Schemas {
			if i == timeFieldIndex {
				continue
			}
			if _, ok := client.VALUE_TYPE_MAP[schema.ValueType]; !ok {
				continue
			}
			if schema.Type == common.COLUMN_SCHEMA_TYPE_TAG {
				seriesSort.SortIndex = append(seriesSort.SortIndex, i)
				seriesSort.Reverse = append(seriesSort.Reverse, false)
			}
		}
		seriesSort.SortIndex = append(seriesSort.SortIndex, timeFieldIndex)
		seriesSort.Reverse = append(seriesSort.Reverse, reverse)
		sort.Sort(seriesSort)
		groups := client.Group(seriesSort.Series, seriesSort.SortIndex[:len(seriesSort.SortIndex)-1], result.Schemas)

		// fix start and end
		newTimeStart := int(m.Time.TimeStart)
		newTimeEnd := int(m.Time.TimeEnd)
		if m.Time.TimeStartOperator == ">" {
			newTimeStart = int(m.Time.TimeStart) + m.Time.Interval
		}
		if m.Time.TimeEndOperator == "<" {
			newTimeEnd = int(m.Time.TimeEnd) - m.Time.Interval
		}
		start := (newTimeStart+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8
		end := (newTimeEnd+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8
		end += (m.Time.WindowSize - 1) * m.Time.Interval
		// length after fix
		intervalLength := (end-start)/m.Time.Interval + 1
		if intervalLength < 1 {
			log.Errorf("Callback Time Fill Error: intervalLength(%d) < 1", intervalLength)
			return errors.New(fmt.Sprintf("Callback Time Fill Error: intervalLength(%d) < 1", intervalLength))
		}
		resultNewValues := []interface{}{}
		timeFillLimit := TIME_FILL_LIMIT_DEFAULT
		if config.Cfg != nil {
			timeFillLimit = config.Cfg.TimeFillLimit
		}
		for i, group := range groups {
			groupIndexs := []int{}
			for _, groupIndex := range group.GroupIndex {
				groupIndexs = append(groupIndexs, groupIndex)
			}
			if timeFillLimit > 0 && i >= timeFillLimit {
				for _, series := range group.Series {
					resultNewValues = append(resultNewValues, series.Values)
				}
				continue
			}
			newValues := make([]interface{}, intervalLength)
			// data from ck insert to newValues
			for _, series := range group.Series {
				record := series.Values
				// get localtion of record in newValues
				var timeIndex int
				if !reverse {
					timeIndex = (record[timeFieldIndex].(int) - start) / m.Time.Interval
				} else {
					timeIndex = (end - record[timeFieldIndex].(int)) / m.Time.Interval
				}
				if timeIndex >= intervalLength || timeIndex < 0 {
					continue
				}
				newValues[timeIndex] = series.Values
			}
			var timestamp int
			// fill point
			for i, value := range newValues {
				if value == nil {
					newValue := make([]interface{}, len(result.Columns))
					for valueIndex, groupIndex := range group.GroupIndex {
						newValue[groupIndex] = group.GroupValues[valueIndex]
					}
					if m.Time.Fill != "null" {
						for i := range newValue {
							if newValue[i] != nil {
								continue
							}
							if intField, err := strconv.Atoi(m.Time.Fill); err == nil {
								newValue[i] = int(intField)
							} else {
								newValue[i] = m.Time.Fill
							}
						}
					}
					if !reverse {
						timestamp = start + i*m.Time.Interval
					} else {
						timestamp = end - i*m.Time.Interval
					}
					newValue[timeFieldIndex] = timestamp
					newValues[i] = newValue
				} else {
					// if point exist && metrics is null, fill the metrics
					switch value.(type) {
					case []interface{}:
						newValue := value.([]interface{})
						for i := range newValue {
							indexOK := slices.Contains[[]int, int](groupIndexs, i)
							if indexOK {
								continue
							}
							if newValue[i] == nil {
								if intField, err := strconv.Atoi(m.Time.Fill); err == nil {
									newValue[i] = int(intField)
								} else {
									newValue[i] = m.Time.Fill
								}
							}
						}
					}
				}
			}
			resultNewValues = append(resultNewValues, newValues...)
		}
		result.Values = resultNewValues
		return nil
	}
}

func MacTranslate(args []interface{}) func(result *common.Result) error {
	return func(result *common.Result) error {
		newValues := make([]interface{}, len(result.Values))
		var macIndex int
		var macTypeIndex int
		macTypeIndex = -1
		for i, column := range result.Columns {
			if column.(string) == args[1].(string) {
				macIndex = i
				break
			}
		}
		for i, column := range result.Columns {
			if column.(string) == "tap_port_type" {
				macTypeIndex = i
				break
			}
		}
		copy(newValues, result.Values)
		for i, newValue := range newValues {
			newValueSlice := newValue.([]interface{})
			switch newValueSlice[macIndex].(type) {
			case int:
				newMac := utils.Uint64ToMac(uint64((newValueSlice[macIndex]).(int))).String()
				if args[0].(string) == "tap_port" && macTypeIndex != -1 {
					newMac = strings.TrimPrefix(newMac, "00:00:")
					if newValueSlice[macTypeIndex].(int) == tag.TAP_PORT_MAC_0 || newValueSlice[macTypeIndex].(int) == tag.TAP_PORT_MAC_1 {
						newValueSlice[macIndex] = newMac
						newValues[i] = newValueSlice
					} else if newValueSlice[macTypeIndex].(int) == tag.TAP_PORT_IPV4 {
						newIP := utils.IpFromUint32(uint32((newValueSlice[macIndex]).(int)))
						newIPString := newIP.String()
						newValueSlice[macIndex] = newIPString
						newValues[i] = newValueSlice
					}
				} else {
					newValueSlice[macIndex] = newMac
					newValues[i] = newValueSlice
				}
			}
		}
		result.Values = newValues
		return nil
	}
}
