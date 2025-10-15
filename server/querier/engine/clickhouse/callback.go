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

package clickhouse

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	chCommon "github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
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
			if schema.Type == common.COLUMN_SCHEMA_TYPE_TAG {
				seriesSort.SortIndex = append(seriesSort.SortIndex, i)
				seriesSort.Reverse = append(seriesSort.Reverse, false)
			}
		}
		seriesSort.SortIndex = append(seriesSort.SortIndex, timeFieldIndex)
		seriesSort.Reverse = append(seriesSort.Reverse, reverse)
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
		start := (newTimeStart-m.Time.Offset+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8 + m.Time.Offset
		end := (newTimeEnd-m.Time.Offset+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8 + m.Time.Offset
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
				timeInt := int(record[timeFieldIndex].(uint32))
				if !reverse {
					timeIndex = (timeInt - start) / m.Time.Interval
				} else {
					timeIndex = (end - timeInt) / m.Time.Interval
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
					newValue[timeFieldIndex] = uint32(timestamp)
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
			if column.(string) == "tap_port_type" || column.(string) == "capture_nic_type" {
				macTypeIndex = i
				break
			}
		}
		copy(newValues, result.Values)
		for i, newValue := range newValues {
			newValueSlice := newValue.([]interface{})
			switch newValueSlice[macIndex].(type) {
			// capture_nic, tunnel_tx_mac_0, tunnel_tx_mac_1, tunnel_rx_mac_0, tunnel_rx_mac_1"
			case uint32:
				mac := newValueSlice[macIndex].(uint32)
				newMac := utils.Uint64ToMac(uint64(mac)).String()
				if (args[0].(string) == "tap_port" || args[0].(string) == "capture_nic") && macTypeIndex != -1 {
					newMac = strings.TrimPrefix(newMac, "00:00:")
					if newValueSlice[macTypeIndex].(uint8) == tag.TAP_PORT_MAC_0 || newValueSlice[macTypeIndex].(uint8) == tag.TAP_PORT_MAC_1 {
						newValueSlice[macIndex] = newMac
						newValues[i] = newValueSlice
					} else if newValueSlice[macTypeIndex].(uint8) == tag.TAP_PORT_IPV4 {
						newIP := utils.IpFromUint32(mac)
						newIPString := newIP.String()
						newValueSlice[macIndex] = newIPString
						newValues[i] = newValueSlice
					}
				} else {
					newValueSlice[macIndex] = newMac
					newValues[i] = newValueSlice
				}
			// mac_0, mac_1
			case uint64:
				mac := newValueSlice[macIndex].(uint64)
				newMac := utils.Uint64ToMac(mac).String()
				newValueSlice[macIndex] = newMac
				newValues[i] = newValueSlice
			}
		}
		result.Values = newValues
		return nil
	}
}

func ColumnNameSwap(args []interface{}) func(result *common.Result) error {
	return func(result *common.Result) error {
		tagName := args[0].(string)
		newColumnNames := make([]interface{}, len(result.Columns))
		for i, columnName := range result.Columns {
			if strings.HasPrefix(columnName.(string), tagName) {
				columnName = strings.TrimPrefix(columnName.(string), tagName+"_")
			}
			newColumnNames[i] = columnName
		}
		result.Columns = newColumnNames
		return nil
	}
}

func TraceIDsToTraceID(args []interface{}) func(result *common.Result) error {
	return func(result *common.Result) error {
		newColumnNames := make([]interface{}, len(result.Columns))
		for i, columnName := range result.Columns {
			if columnName.(string) == chCommon.TRACE_IDS_TAG {
				columnName = chCommon.TRACE_ID_TAG
			}
			newColumnNames[i] = columnName
		}
		result.Columns = newColumnNames
		return nil
	}
}
