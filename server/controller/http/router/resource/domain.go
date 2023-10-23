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

package resource

import (
	"encoding/json"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func DomainRouter(e *gin.Engine, cfg *config.ControllerConfig) {
	// TODO: 后续统一为v2
	e.GET("/v2/domains/:lcuuid/", getDomain)
	e.GET("/v2/domains/", getDomains)
	e.POST("/v1/domains/", createDomain(cfg))
	e.PATCH("/v1/domains/:lcuuid/", updateDomain(cfg))
	e.DELETE("/v1/domains/:name-or-uuid/", deleteDomainByNameOrUUID)

	e.GET("/v2/sub-domains/:lcuuid/", getSubDomain)
	e.GET("/v2/sub-domains/", getSubDomains)
	e.POST("/v2/sub-domains/", createSubDomain)
	e.PATCH("/v2/sub-domains/:lcuuid/", updateSubDomain)
	e.DELETE("/v2/sub-domains/:lcuuid/", deleteSubDomain)

	e.PUT("/v1/domain-additional-resources/", applyDomainAddtionalResource)
}

func getDomain(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := GetDomains(args)
	JsonResponse(c, data, err)
}

func getDomains(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("name"); ok {
		args["name"] = value
	}
	data, err := GetDomains(args)
	JsonResponse(c, data, err)
}

func createDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var domainCreate model.DomainCreate

		// message validation
		err = c.ShouldBindBodyWith(&domainCreate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}

		data, err := CreateDomain(domainCreate, cfg)
		JsonResponse(c, data, err)
	})
}

func updateDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var domainUpdate model.DomainUpdate

		// message validation
		err = c.ShouldBindBodyWith(&domainUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
			return
		}

		// transfer json format to map
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")
		data, err := UpdateDomain(lcuuid, patchMap, cfg)
		JsonResponse(c, data, err)
	})
}

func deleteDomainByNameOrUUID(c *gin.Context) {
	nameOrUUID := c.Param("name-or-uuid")
	data, err := DeleteDomainByNameOrUUID(nameOrUUID)
	JsonResponse(c, data, err)
}

func getSubDomain(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := GetSubDomains(args)
	JsonResponse(c, data, err)
}

func getSubDomains(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("domain"); ok {
		args["domain"] = value
	}
	if value, ok := c.GetQuery("cluster_id"); ok {
		args["cluster_id"] = value
	}
	data, err := GetSubDomains(args)
	JsonResponse(c, data, err)
}

func createSubDomain(c *gin.Context) {
	var err error
	var subDomainCreate model.SubDomainCreate

	// 参数校验
	err = c.ShouldBindBodyWith(&subDomainCreate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
		return
	}

	data, err := CreateSubDomain(subDomainCreate)
	JsonResponse(c, data, err)
}

func deleteSubDomain(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := DeleteSubDomain(lcuuid)
	JsonResponse(c, data, err)
}

func updateSubDomain(c *gin.Context) {
	var err error
	var subDomainUpdate model.SubDomainUpdate

	// 参数校验
	err = c.ShouldBindBodyWith(&subDomainUpdate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	// 避免struct会有默认值，这里转为map作为函数入参
	patchMap := map[string]interface{}{}
	c.ShouldBindBodyWith(&patchMap, binding.JSON)

	lcuuid := c.Param("lcuuid")
	data, err := UpdateSubDomain(lcuuid, patchMap)
	JsonResponse(c, data, err)
}

func applyDomainAddtionalResource(c *gin.Context) {
	b, err := io.ReadAll(c.Request.Body)
	if err != nil {
		BadRequestResponse(c, common.SERVER_ERROR, err.Error())
		return
	}
	err = CheckJSONParam(string(b), model.AdditionalResource{})
	if err != nil {
		BadRequestResponse(c, common.PARAMETER_ILLEGAL, err.Error())
		return
	}

	var data model.AdditionalResource
	err = json.Unmarshal(b, &data)
	// invalidate request body
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	err = ApplyDomainAddtionalResource(data)
	JsonResponse(c, map[string]interface{}{}, err)
}
