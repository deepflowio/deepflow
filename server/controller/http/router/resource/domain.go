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

package resource

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource"
	"github.com/deepflowio/deepflow/server/controller/model"
)

var log = logging.MustGetLogger("controller.resource")

type Domain struct {
	cfg *config.ControllerConfig
}

func NewDomain(cfg *config.ControllerConfig) *Domain {
	return &Domain{cfg: cfg}
}

func (d *Domain) RegisterTo(e *gin.Engine) {
	// TODO: 后续统一为v2
	e.GET("/v2/domains/:lcuuid/", getDomain)
	e.GET("/v2/domains/", getDomains)
	e.POST("/v1/domains/", createDomain(d.cfg))
	e.PATCH("/v1/domains/:lcuuid/", updateDomain(d.cfg))
	e.DELETE("/v1/domains/:name-or-uuid/", deleteDomainByNameOrUUID)
	e.DELETE("/v1/domains/", deleteDomainByName)

	e.GET("/v2/sub-domains/:lcuuid/", getSubDomain)
	e.GET("/v2/sub-domains/", getSubDomains)
	e.POST("/v2/sub-domains/", createSubDomain)
	e.PATCH("/v2/sub-domains/:lcuuid/", updateSubDomain)
	e.DELETE("/v2/sub-domains/:lcuuid/", deleteSubDomain)

	e.PUT("/v1/domain-additional-resources/", applyDomainAddtionalResource)
	e.GET("/v1/domain-additional-resources/", listDomainAddtionalResource)
}

func getDomain(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := resource.GetDomains(args)
	common.JsonResponse(c, data, err)
}

func getDomains(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("name"); ok {
		args["name"] = value
	}
	data, err := resource.GetDomains(args)
	common.JsonResponse(c, data, err)
}

func createDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var domainCreate model.DomainCreate

		// message validation
		err = c.ShouldBindBodyWith(&domainCreate, binding.JSON)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
			return
		}

		data, err := resource.CreateDomain(domainCreate, cfg)
		common.JsonResponse(c, data, err)
	})
}

func updateDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var domainUpdate model.DomainUpdate

		// message validation
		err = c.ShouldBindBodyWith(&domainUpdate, binding.JSON)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		var vTapValue string
		v, ok := domainUpdate.Config["vtap_id"]
		if ok && v != nil {
			vTapValue = v.(string)
		}

		// transfer json format to map
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")

		// set vtap
		err = resource.KubernetesSetVtap(lcuuid, vTapValue, false)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.K8S_SET_VTAP_FAIL, err.Error())
			return
		}

		data, err := resource.UpdateDomain(lcuuid, patchMap, cfg)
		common.JsonResponse(c, data, err)
	})
}

func deleteDomainByNameOrUUID(c *gin.Context) {
	nameOrUUID := c.Param("name-or-uuid")
	data, err := resource.DeleteDomainByNameOrUUID(nameOrUUID)
	common.JsonResponse(c, data, err)
}

func deleteDomainByName(c *gin.Context) {
	rawQuery := strings.Split(c.Request.URL.RawQuery, "name=")
	if len(rawQuery) < 1 {
		common.JsonResponse(c, nil, fmt.Errorf("please fill in the name parameter: domains/?name={}"))
		return
	}
	name := rawQuery[1]
	name, err := url.QueryUnescape(name)
	if err != nil {
		log.Warning(err)
		name = rawQuery[1]
	}
	log.Infof("delete domain by name(%v)", name)
	data, err := resource.DeleteDomainByNameOrUUID(name)
	common.JsonResponse(c, data, err)
}

func getSubDomain(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := resource.GetSubDomains(args)
	common.JsonResponse(c, data, err)
}

func getSubDomains(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("domain"); ok {
		args["domain"] = value
	}
	if value, ok := c.GetQuery("cluster_id"); ok {
		args["cluster_id"] = value
	}
	data, err := resource.GetSubDomains(args)
	common.JsonResponse(c, data, err)
}

func createSubDomain(c *gin.Context) {
	var err error
	var subDomainCreate model.SubDomainCreate

	// 参数校验
	err = c.ShouldBindBodyWith(&subDomainCreate, binding.JSON)
	if err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
		return
	}

	data, err := resource.CreateSubDomain(subDomainCreate)
	common.JsonResponse(c, data, err)
}

func deleteSubDomain(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := resource.DeleteSubDomain(lcuuid)
	common.JsonResponse(c, data, err)
}

func updateSubDomain(c *gin.Context) {
	var err error
	var subDomainUpdate model.SubDomainUpdate

	// 参数校验
	err = c.ShouldBindBodyWith(&subDomainUpdate, binding.JSON)
	if err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}

	var vTapValue string
	v, ok := subDomainUpdate.Config["vtap_id"]
	if ok && v != nil {
		vTapValue = v.(string)
	}

	// 接收参数
	// 避免struct会有默认值，这里转为map作为函数入参
	patchMap := map[string]interface{}{}
	c.ShouldBindBodyWith(&patchMap, binding.JSON)

	lcuuid := c.Param("lcuuid")

	err = resource.KubernetesSetVtap(lcuuid, vTapValue, true)
	if err != nil {
		common.BadRequestResponse(c, httpcommon.K8S_SET_VTAP_FAIL, err.Error())
		return
	}

	data, err := resource.UpdateSubDomain(lcuuid, patchMap)
	common.JsonResponse(c, data, err)
}

func applyDomainAddtionalResource(c *gin.Context) {
	b, err := io.ReadAll(c.Request.Body)
	if err != nil {
		common.BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
		return
	}
	err = common.CheckJSONParam(string(b), model.AdditionalResource{})
	if err != nil {
		common.BadRequestResponse(c, httpcommon.PARAMETER_ILLEGAL, err.Error())
		return
	}

	var data model.AdditionalResource
	err = json.Unmarshal(b, &data)
	// invalidate request body
	if err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}

	err = resource.ApplyDomainAddtionalResource(data)
	common.JsonResponse(c, map[string]interface{}{}, err)
}

func listDomainAddtionalResource(c *gin.Context) {
	var resourceType, resourceName string
	t, ok := c.GetQuery("type")
	if ok {
		resourceType = t
	}
	name, ok := c.GetQuery("name")
	if ok {
		resourceName = name
	}
	if resourceName != "" && resourceType == "" {
		common.JsonResponse(c, httpcommon.PARAMETER_ILLEGAL, fmt.Errorf("please enter resource type, resource name(%v)", resourceName))
		return
	}

	data, err := resource.ListDomainAdditionalResource(resourceType, resourceName)
	common.JsonResponse(c, data, err)
}
