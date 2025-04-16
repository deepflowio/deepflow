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

package router

import (
	"encoding/csv"
	"fmt"
	"github.com/gin-gonic/gin"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service/vtap"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type VTapInterface struct {
	cfg ctrlrcommon.FPermit
}

func NewVTapInterface(cfg ctrlrcommon.FPermit) *VTapInterface {
	return &VTapInterface{cfg: cfg}
}

func (v *VTapInterface) RegisterTo(e *gin.Engine) {
	e.GET("/v1/vtap-interfaces/", v.getVTapInterfaces())
	e.GET("/v1/vtap-interfaces/download", v.downloadVTapInterfaces())
}

func (v *VTapInterface) getVTapInterfaces() gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("team_id"); ok {
			args["team_id"] = value
		}
		if value, ok := c.GetQuery("user_id"); ok {
			args["user_id"] = value
		}

		fuzzyFields := []string{"name", "mac", "device_name", "vtap_name", "tap_name", "tap_mac"}
		for _, field := range fuzzyFields {
			if value, ok := c.GetQuery("fuzzy_" + field); ok {
				if strings.TrimSpace(value) == "" {
					response.JSON(c, response.SetData(nil), response.SetError(fmt.Errorf("fuzzy_%s cannot be empty", field)))
					return
				}
				args["fuzzy_"+field] = value
			}
		}

		for _, field := range []string{"page_index", "page_size"} {
			if v, ok := c.GetQuery(field); ok {
				value, err := strconv.Atoi(v)
				if err != nil {
					response.JSON(c, response.SetData(nil), response.SetError(fmt.Errorf("%s must be an integer", field)))
					return
				}
				args[field] = value
			}
		}

		for _, field := range []string{"device_type", "vtap_type"} {
			if values := c.QueryArray(field); len(values) > 0 {
				intValues := make([]int, 0, len(values))
				for _, v := range values {
					if intVal, err := strconv.Atoi(v); err == nil {
						intValues = append(intValues, intVal)
					}
				}
				if len(intValues) > 0 {
					args[field] = intValues
				}
			}
		}

		data, page, err := vtap.NewVTapInterface(v.cfg, httpcommon.GetUserInfo(c)).Get(args)
		response.JSON(c, response.SetData(data), response.SetPage(*page), response.SetError(err))
	}
}

func (v *VTapInterface) downloadVTapInterfaces() gin.HandlerFunc {
	return func(c *gin.Context) {
		data, _, err := vtap.NewVTapInterface(v.cfg, httpcommon.GetUserInfo(c)).Get(make(map[string]interface{}))
		fields := c.QueryArray("field")
		format := c.Query("format")
		if format == "csv" {
			dataBytes, err := convertVTapInterfacesToCSV(data, fields)
			response.DownloadCSV(
				c,
				fmt.Sprintf("deepflow-%s-%s-%s.csv", "vtap-interfaces",
					time.Now().Format("20060102"), time.Now().Format("150405")),
				response.SetData(dataBytes),
				response.SetError(err),
			)
		} else {
			response.JSON(c, response.SetData(data), response.SetError(err))
		}
	}
}

// convert []model.VTapInterface to csv, use strings.Builder and csv.NewWriter
func convertVTapInterfacesToCSV(vifs []model.VTapInterface, columns []string) ([]byte, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	// 获取所有字段名和对应的字段索引映射
	if len(columns) == 0 {
		columns = []string{}
		t := reflect.TypeOf(model.VTapInterface{})
		for i := 0; i < t.NumField(); i++ {
			columns = append(columns, t.Field(i).Tag.Get("json"))
		}
	}

	// 预先创建字段索引映射，避免在循环中重复查找
	fieldIndices := make(map[string]int)
	vType := reflect.TypeOf(model.VTapInterface{})
	for i := 0; i < vType.NumField(); i++ {
		field := vType.Field(i)
		jsonTag := field.Tag.Get("json")
		if idx := strings.Index(jsonTag, ","); idx != -1 {
			jsonTag = jsonTag[:idx]
		}
		fieldIndices[jsonTag] = i
	}

	if err := writer.Write(columns); err != nil {
		return nil, fmt.Errorf("write headers failed: %w", err)
	}

	// 使用对象池来复用切片，减少内存分配
	pool := sync.Pool{
		New: func() interface{} {
			return make([]string, len(columns))
		},
	}

	const batchSize = 1000
	for i := 0; i < len(vifs); i += batchSize {
		end := i + batchSize
		if end > len(vifs) {
			end = len(vifs)
		}

		// 批量处理数据
		for _, vif := range vifs[i:end] {
			values := pool.Get().([]string)
			vValue := reflect.ValueOf(vif)

			for j, column := range columns {
				if fieldIndex, ok := fieldIndices[column]; ok {
					field := vValue.Field(fieldIndex)
					values[j] = formatVTapVInterfaceValue(field)
				}
			}

			if err := writer.Write(values); err != nil {
				pool.Put(values)
				return nil, fmt.Errorf("write row failed: %w", err)
			}
			pool.Put(values)
		}

		// 定期刷新，避免缓冲区过大
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, fmt.Errorf("flush writer failed: %w", err)
		}
	}

	return []byte(sb.String()), nil
}

// formatVTapVInterfaceValue 格式化字段值，处理特殊类型
func formatVTapVInterfaceValue(v reflect.Value) string {
	switch v.Kind() {
	case reflect.Int:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.String:
		return v.String()
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}
