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

package clickhouse

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/deepflowys/deepflow/server/libs/utils"
	"github.com/deepflowys/deepflow/server/querier/common"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/tag"
	"github.com/deepflowys/deepflow/server/querier/engine/clickhouse/view"
)

type Callback struct {
	Args     []interface{}
	Function func([]interface{}) func(*common.Result) error
	Column   string
}

func (c *Callback) Format(m *view.Model) {
	m.AddCallback(c.Column, c.Function(c.Args))
}

func TimeFill(args []interface{}) func(result *common.Result) error {
	// group by time时的补点
	return func(result *common.Result) error {
		m := args[0].(*view.Model)
		var timeFieldIndex int
		// 取出time字段对应的下标
		for i, column := range result.Columns {
			if column.(string) == strings.Trim(m.Time.Alias, "`") {
				timeFieldIndex = i
				break
			}
		}
		// start和end取整
		start := (int(m.Time.TimeStart)+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8
		end := (int(m.Time.TimeEnd)+3600*8)/m.Time.Interval*m.Time.Interval - 3600*8
		// 获取排序
		orderby := "asc"
		for _, node := range m.Orders.Orders {
			order := node.(*view.Order)
			if strings.Trim(order.SortBy, "`") == strings.Trim(m.Time.Alias, "`") {
				orderby = order.OrderBy
				break
			}
		}
		end += (m.Time.WindowSize - 1) * m.Time.Interval
		// 补点后切片长度
		intervalLength := (end-start)/m.Time.Interval + 1
		if intervalLength < 1 {
			log.Errorf("Callback Time Fill Error: intervalLength(%d) < 1", intervalLength)
			return errors.New(fmt.Sprintf("Callback Time Fill Error: intervalLength(%d) < 1", intervalLength))
		}
		newValues := make([]interface{}, intervalLength)
		// 将查询数据结果写入newValues切片
		for _, value := range result.Values {
			record := value.([]interface{})
			// 获取record在补点切片中的位置
			var timeIndex int
			if orderby == "asc" {
				timeIndex = (record[timeFieldIndex].(int) - start) / m.Time.Interval
			} else {
				timeIndex = (end - record[timeFieldIndex].(int)) / m.Time.Interval
			}
			if timeIndex >= intervalLength || timeIndex < 0 {
				continue
			}
			newValues[timeIndex] = value
		}
		var timestamp int
		// 针对newValues中缺少的时间点进行补点
		for i, value := range newValues {
			if value == nil {
				newValue := make([]interface{}, len(result.Columns))
				if m.Time.Fill != "null" {
					for i := range newValue {
						if intField, err := strconv.Atoi(m.Time.Fill); err == nil {
							newValue[i] = int(intField)
						} else {
							newValue[i] = m.Time.Fill
						}
					}
				}
				if orderby == "asc" {
					timestamp = start + i*m.Time.Interval
				} else {
					timestamp = end - i*m.Time.Interval
				}
				newValue[timeFieldIndex] = timestamp
				newValues[i] = newValue
			}
		}
		result.Values = newValues
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
		for i, value := range result.Values {
			newValues[i] = value
		}
		for i, newValue := range newValues {
			newValueSlice := newValue.([]interface{})
			switch newValueSlice[macIndex].(type) {
			case int:
				newMac := utils.Uint64ToMac(uint64((newValueSlice[macIndex]).(int))).String()
				if args[0].(string) == "tap_port" && macTypeIndex != -1 {
					newMac = strings.TrimPrefix(newMac, "00:00:")
					if newValueSlice[macTypeIndex].(uint8) == tag.TAP_PORT_MAC_0 || newValueSlice[macTypeIndex].(uint8) == tag.TAP_PORT_MAC_1 {
						newValueSlice[macIndex] = newMac
						newValues[i] = newValueSlice
					} else if newValueSlice[macTypeIndex].(uint8) == tag.TAP_PORT_IPV4 {
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

func ExternalTagsFormat(args []interface{}) func(result *common.Result) error {
	return func(result *common.Result) error {
		newValues := []interface{}{}
		var tagsIndex int
		for i, column := range result.Columns {
			if column.(string) == args[0].(string) {
				tagsIndex = i
				break
			}
		}
		for _, newValue := range result.Values {
			newValueSlice := newValue.([]interface{})
			tagsMap := make(map[string]interface{})
			for _, tagValue := range newValueSlice[tagsIndex].([][]interface{}) {
				if len(tagValue) == 2 {
					tagsMap[tagValue[0].(string)] = tagValue[1]
				}
			}
			tagsStr, err := json.Marshal(tagsMap)
			if err != nil {
				log.Error(err)
				result.Values = newValues
				return err
			}
			newValueSlice[tagsIndex] = string(tagsStr)
			newValues = append(newValues, newValueSlice)
		}
		result.Values = newValues
		return nil
	}
}
