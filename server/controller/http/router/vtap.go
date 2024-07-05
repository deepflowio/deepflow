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
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/election"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
)

type Vtap struct {
	cfg *config.ControllerConfig
}

func NewVtap(cfg *config.ControllerConfig) *Vtap {
	return &Vtap{cfg: cfg}
}

func (v *Vtap) RegisterTo(e *gin.Engine) {
	e.GET("/v1/vtaps/:lcuuid/", v.getVtap())
	e.GET("/v1/vtaps/", v.getVtaps())
	e.POST("/v1/vtaps/", v.createVtap())
	e.PATCH("/v1/vtaps/:lcuuid/", v.updateVtap())
	e.PATCH("/v1/vtaps-by-name/:name/", v.updateVtap())
	e.DELETE("/v1/vtaps/:lcuuid/", v.deleteVtap())
	e.POST("/v1/vtaps/batch/", v.batchUpdateVtap())
	e.DELETE("/v1/vtaps/batch/", v.batchDeleteVtap())

	e.POST("/v1/rebalance-vtap/", rebalanceVtap(v.cfg))

	e.PATCH("/v1/vtaps-license-type/:lcuuid/", v.updateVtapLicenseType())
	e.PATCH("/v1/vtaps-license-type/", v.batchUpdateVtapLicenseType())

	e.POST("/v1/vtaps-csv/", v.getVtapCSV())

	e.GET("/v1/vtap-ports/", getVTapPorts) // only in default organization
}

func (v *Vtap) getVtap() gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		args["lcuuid"] = c.Param("lcuuid")
		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).Get(args)
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) getVtaps() gin.HandlerFunc {
	return func(c *gin.Context) {
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
		if value, ok := c.GetQuery("team_id"); ok {
			args["team_id"] = value
		}
		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).Get(args)
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) createVtap() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		var vtapCreate model.VtapCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapCreate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).Create(vtapCreate)
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) updateVtap() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		var vtapUpdate model.VtapUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")
		name := c.Param("name")
		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).Update(lcuuid, name, patchMap)
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) batchUpdateVtap() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error

		// 参数校验
		vtapUpdateList := make(map[string][]model.VtapUpdate)
		err = c.ShouldBindBodyWith(&vtapUpdateList, binding.JSON)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		updateMap := make(map[string]([]map[string]interface{}))
		c.ShouldBindBodyWith(&updateMap, binding.JSON)

		// 参数校验
		if _, ok := updateMap["DATA"]; !ok {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "No DATA in request body")
		}

		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).BatchUpdate(updateMap["DATA"])
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) updateVtapLicenseType() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		var vtapUpdate model.VtapUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")
		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).UpdateVtapLicenseType(lcuuid, patchMap)
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) batchUpdateVtapLicenseType() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error

		// 参数校验
		vtapUpdateList := make(map[string][]model.VtapUpdate)
		err = c.ShouldBindBodyWith(&vtapUpdateList, binding.JSON)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		updateMap := make(map[string]([]map[string]interface{}))
		c.ShouldBindBodyWith(&updateMap, binding.JSON)

		// 参数校验
		if _, ok := updateMap["DATA"]; !ok {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "No DATA in request body")
		}

		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).BatchUpdateVtapLicenseType(updateMap["DATA"])
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) deleteVtap() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error

		lcuuid := c.Param("lcuuid")
		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).Delete(lcuuid)
		JsonResponse(c, data, err)
	}
}

func (v *Vtap) batchDeleteVtap() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error

		// 接收参数
		deleteMap := make(map[string][](map[string]string))
		c.ShouldBindBodyWith(&deleteMap, binding.JSON)

		// 参数校验
		if _, ok := deleteMap["DATA"]; !ok {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "No DATA in request body")
			return
		}

		data, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).BatchDelete(deleteMap["DATA"])
		JsonResponse(c, data, err)
	}
}

func rebalanceVtap(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// 如果不是masterController，将请求转发至是masterController
		isMasterController, masterControllerIP, _ := election.IsMasterControllerAndReturnIP()
		if !isMasterController {
			ForwardMasterController(c, masterControllerIP, cfg.ListenPort)
			return
		}

		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		dbInfo, err := mysql.GetDB(orgID.(int))
		if err != nil {
			JsonResponse(c, nil, err)
			return
		}

		args := make(map[string]interface{})
		args["check"] = false
		if value, ok := c.GetQuery("check"); ok {
			args["check"] = (strings.ToLower(value) == "true")
		}
		if isDebug, ok := c.GetQuery("is_debug"); ok {
			args["is_debug"] = (strings.ToLower(isDebug) == "true")
		}
		if value, ok := c.GetQuery("type"); ok {
			args["type"] = value
			if args["type"] != "controller" && args["type"] != "analyzer" {
				BadRequestResponse(
					c, httpcommon.INVALID_PARAMETERS,
					fmt.Sprintf("ORG(id=%d database=%s) type (%s) is not supported", dbInfo.ORGID, dbInfo.Name, args["type"]),
				)
				return
			}
		} else {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "must specify type")
			return
		}

		data, err := service.VTapRebalance(dbInfo, args, cfg.MonitorCfg.IngesterLoadBalancingConfig)
		if err != nil {
			JsonResponse(c, nil, fmt.Errorf("ORG(id=%d database=%s) %s", dbInfo.ORGID, dbInfo.Name, err.Error()))
			return
		}
		JsonResponse(c, data, nil)
	})
}

func (v *Vtap) getVtapCSV() gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.GetPostForm("CSV_HEADERS")
		if !ok {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "can not not get form data(CSV_HEADERS)")
			return
		}
		var headers []model.CSVHeader
		if err := json.Unmarshal([]byte(value), &headers); err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "parse form data(CSV_HEADERS) failed")
			return
		}

		vtaps, err := service.NewAgent(httpcommon.GetUserInfo(c), v.cfg).Get(nil)
		if err != nil {
			BadRequestResponse(c, httpcommon.SERVER_ERROR, "get vtaps failed")
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

func getVTapPorts(c *gin.Context) {
	count, err := service.GetVTapPortsCount()
	if err != nil {
		BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
		return
	}
	resp := map[string]int{
		"COUNT": count,
	}
	JsonResponse(c, resp, nil)
}
