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

package router

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func VtapRouter(e *gin.Engine) {
	e.GET("/v1/vtaps/:lcuuid/", getVtap)
	e.GET("/v1/vtaps/", getVtaps)
	e.POST("/v1/vtaps/", createVtap)
	e.PATCH("/v1/vtaps/:lcuuid/", updateVtap)
	e.PATCH("/v1/vtaps-by-name/:name/", updateVtap)
	e.DELETE("/v1/vtaps/:lcuuid/", deleteVtap)
	e.POST("/v1/vtaps/batch/", batchUpdateVtap)
	e.DELETE("/v1/vtaps/batch/", batchDeleteVtap)

	e.POST("/v1/rebalance-vtap/", rebalanceVtap)

	e.PATCH("/v1/vtaps-license-type/:lcuuid/", updateVtapLicenseType)
	e.PATCH("/v1/vtaps-license-type/", batchUpdateVtapLicenseType)
	e.PATCH("/v1/vtaps-tap-mode/", batchUpdateVtapTapMode)

	e.POST("/v1/vtaps-csv/", getVtapCSV)
}

func getVtap(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetVtaps(args)
	JsonResponse(c, data, err)
}

func getVtaps(c *gin.Context) {
	args := make(map[string]interface{})
	args["names"] = c.QueryArray("name")
	if value, ok := c.GetQuery("type"); ok {
		args["type"] = value
	}
	if value, ok := c.GetQuery("vtap_group_lcuuid"); ok {
		args["vtap_group_lcuuid"] = value
	}
	if value, ok := c.GetQuery("controller_ip"); ok {
		args["controller_ip"] = value
	}
	if value, ok := c.GetQuery("analyzer_ip"); ok {
		args["analyzer_ip"] = value
	}
	data, err := service.GetVtaps(args)
	JsonResponse(c, data, err)
}

func createVtap(c *gin.Context) {
	var err error
	var vtapCreate model.VtapCreate

	// 参数校验
	err = c.ShouldBindBodyWith(&vtapCreate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	data, err := service.CreateVtap(vtapCreate)
	JsonResponse(c, data, err)
}

func updateVtap(c *gin.Context) {
	var err error
	var vtapUpdate model.VtapUpdate

	// 参数校验
	err = c.ShouldBindBodyWith(&vtapUpdate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	// 避免struct会有默认值，这里转为map作为函数入参
	patchMap := map[string]interface{}{}
	c.ShouldBindBodyWith(&patchMap, binding.JSON)

	lcuuid := c.Param("lcuuid")
	name := c.Param("name")
	data, err := service.UpdateVtap(lcuuid, name, patchMap)
	JsonResponse(c, data, err)
}

func batchUpdateVtap(c *gin.Context) {
	var err error

	// 参数校验
	vtapUpdateList := make(map[string][]model.VtapUpdate)
	err = c.ShouldBindBodyWith(&vtapUpdateList, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	updateMap := make(map[string]([]map[string]interface{}))
	c.ShouldBindBodyWith(&updateMap, binding.JSON)

	// 参数校验
	if _, ok := updateMap["DATA"]; !ok {
		BadRequestResponse(c, common.INVALID_PARAMETERS, "No DATA in request body")
	}

	data, err := service.BatchUpdateVtap(updateMap["DATA"])
	JsonResponse(c, data, err)
}

func updateVtapLicenseType(c *gin.Context) {
	var err error
	var vtapUpdate model.VtapUpdate

	// 参数校验
	err = c.ShouldBindBodyWith(&vtapUpdate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	// 避免struct会有默认值，这里转为map作为函数入参
	patchMap := map[string]interface{}{}
	c.ShouldBindBodyWith(&patchMap, binding.JSON)

	lcuuid := c.Param("lcuuid")
	data, err := service.UpdateVtapLicenseType(lcuuid, patchMap)
	JsonResponse(c, data, err)
}

func batchUpdateVtapLicenseType(c *gin.Context) {
	var err error

	// 参数校验
	vtapUpdateList := make(map[string][]model.VtapUpdate)
	err = c.ShouldBindBodyWith(&vtapUpdateList, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	updateMap := make(map[string]([]map[string]interface{}))
	c.ShouldBindBodyWith(&updateMap, binding.JSON)

	// 参数校验
	if _, ok := updateMap["DATA"]; !ok {
		BadRequestResponse(c, common.INVALID_PARAMETERS, "No DATA in request body")
	}

	data, err := service.BatchUpdateVtapLicenseType(updateMap["DATA"])
	JsonResponse(c, data, err)
}

func deleteVtap(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := service.DeleteVtap(lcuuid)
	JsonResponse(c, data, err)
}

func batchDeleteVtap(c *gin.Context) {
	var err error

	// 接收参数
	deleteMap := make(map[string][](map[string]string))
	c.ShouldBindBodyWith(&deleteMap, binding.JSON)

	// 参数校验
	if _, ok := deleteMap["DATA"]; !ok {
		BadRequestResponse(c, common.INVALID_PARAMETERS, "No DATA in request body")
		return
	}

	data, err := service.BatchDeleteVtap(deleteMap["DATA"])
	JsonResponse(c, data, err)
}

func rebalanceVtap(c *gin.Context) {
	args := make(map[string]interface{})
	args["check"] = false
	if value, ok := c.GetQuery("check"); ok {
		args["check"] = (strings.ToLower(value) == "true")
	}
	if value, ok := c.GetQuery("type"); ok {
		args["type"] = value
		if args["type"] != "controller" && args["type"] != "analyzer" {
			BadRequestResponse(
				c, common.INVALID_PARAMETERS,
				fmt.Sprintf("type (%s) is not supported", args["type"]),
			)
			return
		}
	} else {
		BadRequestResponse(c, common.INVALID_PARAMETERS, "must specify type")
		return
	}
	data, err := service.VTapRebalance(args)
	JsonResponse(c, data, err)
}

func batchUpdateVtapTapMode(c *gin.Context) {
	var err error
	var vtapUpdateTapMode model.VtapUpdateTapMode

	err = c.ShouldBindBodyWith(&vtapUpdateTapMode, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	if len(vtapUpdateTapMode.VTapLcuuids) == 0 {
		BadRequestResponse(c, common.INVALID_PARAMETERS, "VTAP_LCUUIDS cannot be empty")
		return
	}
	data, err := service.BatchUpdateVtapTapMode(&vtapUpdateTapMode)
	JsonResponse(c, data, err)
}

func getVtapCSV(c *gin.Context) {
	value, ok := c.GetPostForm("CSV_HEADERS")
	if !ok {
		BadRequestResponse(c, common.INVALID_PARAMETERS, "can not not get form data(CSV_HEADERS)")
		return
	}
	var headers []model.CSVHeader
	if err := json.Unmarshal([]byte(value), &headers); err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, "parse form data(CSV_HEADERS) failed")
		return
	}

	vtaps, err := service.GetVtaps(nil)
	if err != nil {
		BadRequestResponse(c, common.SERVER_ERROR, "get vtaps failed")
		return
	}

	buf := new(bytes.Buffer)
	buf.WriteString("\xEF\xBB\xBF")
	w := csv.NewWriter(buf)
	// write header
	var writeHeaders []string
	headerMap := make(map[string]int)
	for i, header := range headers {
		writeHeaders = append(writeHeaders, header.DisplayName)
		headerMap[header.FieldName] = i
	}
	w.Write(writeHeaders)
	// write data
	for _, vtap := range vtaps {
		data := getVtapCSVData(headerMap, &vtap)
		w.Write(data)
	}
	w.Flush()
	c.Writer.Header().Add("Content-type", "application/octet-stream")
	fileName := fmt.Sprintf("DeepFlow-采集器列表-%s.csv", time.Now().Format("2006-01-02"))
	fileName = url.QueryEscape(fileName)
	c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=utf-8''%s", fileName))
	_, err = io.Copy(c.Writer, buf)
}

func getVtapCSVData(headerMap map[string]int, vtap *model.Vtap) []string {
	resp := make([]string, len(headerMap))
	elem := reflect.ValueOf(vtap).Elem()
	for i := 0; i < elem.NumField(); i++ {
		tag := elem.Type().Field(i).Tag
		jsonTag := tag.Get("json")
		if jsonTag == "" {
			log.Warning("json tag not found")
			continue
		}

		index, ok := headerMap[jsonTag]
		if !ok {
			continue
		}
		value := fmt.Sprintf("%v", elem.Field(i))
		if jsonTag == "TYPE" {
			value = common.VTapTypeChinese[vtap.Type]
		} else if jsonTag == "TAP_MODE" {
			value = common.VtapTapModeName[vtap.TapMode]
		} else if jsonTag == "STATE" {
			value = common.VTapStateToChinese[vtap.State]
		} else if jsonTag == "BOOT_TIME" {
			if elem.Field(i).Int() == 0 {
				value = ""
			} else {
				value = time.Unix(int64(vtap.BootTime), 0).Format(common.GO_BIRTHDAY)
			}
		} else if jsonTag == "EXCEPTIONS" {
			var exceptions string
			for i, e := range vtap.Exceptions {
				if i == 0 {
					exceptions = common.VTapExceptionChinese[e]
					continue
				}
				exceptions += fmt.Sprintf("、%s", common.VTapExceptionChinese[e])
			}
			value = exceptions
		}
		resp[index] = value
	}

	return resp
}
