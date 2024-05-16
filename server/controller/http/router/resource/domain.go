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
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/controller/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/router/common"
	svc "github.com/deepflowio/deepflow/server/controller/http/service"
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

// TODO: 后续通过header中携带的用户信息校验用户权限
func (d *Domain) RegisterTo(e *gin.Engine) {
	// TODO: 后续统一为v2
	e.GET("/v2/domains/:lcuuid/", getDomain(d.cfg))
	e.GET("/v2/domains/", getDomains(d.cfg))
	e.POST("/v1/domains/", createDomain(d.cfg))
	e.PATCH("/v1/domains/:lcuuid/", updateDomain(d.cfg))
	e.DELETE("/v1/domains/:name-or-uuid/", deleteDomainByNameOrUUID(d.cfg))
	e.DELETE("/v1/domains/", deleteDomainByName(d.cfg))

	e.GET("/v2/sub-domains/:lcuuid/", getSubDomain(d.cfg))
	e.GET("/v2/sub-domains/", getSubDomains(d.cfg))
	e.POST("/v2/sub-domains/", createSubDomain(d.cfg))
	e.PATCH("/v2/sub-domains/:lcuuid/", updateSubDomain(d.cfg))
	e.DELETE("/v2/sub-domains/:lcuuid/", deleteSubDomain(d.cfg))

	e.PUT("/v1/domain-additional-resources/", applyDomainAddtionalResource)
	e.GET("/v1/domain-additional-resources/", listDomainAddtionalResource)
	e.GET("/v1/domain-additional-resources/example/", GetDomainAdditionalResourceExample)
	e.PATCH("/v1/domain-additional-resources/advanced/", updateDomainAddtionalResourceAdvanced)
	e.GET("/v1/domain-additional-resources/advanced/", getDomainAddtionalResourceAdvanced)
}

func getDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]interface{})
		args["lcuuid"] = c.Param("lcuuid")
		if uValue, ok := c.GetQuery("user_id"); ok {
			userID, err := strconv.Atoi(uValue)
			if err != nil {
				common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
				return
			}
			args["user_id"] = userID
		}
		if tValue, ok := c.GetQuery("team_id"); ok {
			teamID, err := strconv.Atoi(tValue)
			if err != nil {
				common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
				return
			}
			args["team_id"] = teamID
		}
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}
		excludeTeamIDs := []int{}
		teamIDs, err := svc.GetUnauthorizedTeamIDs(svc.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.CHECK_SCOPE_TEAMS_FAIL, err.Error())
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetDomains(db, excludeTeamIDs, args)
		common.JsonResponse(c, data, err)
	})
}

func getDomains(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("name"); ok {
			args["name"] = value
		}
		if uValue, ok := c.GetQuery("user_id"); ok {
			userID, err := strconv.Atoi(uValue)
			if err != nil {
				common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
				return
			}
			args["user_id"] = userID
		}
		if tValue, ok := c.GetQuery("team_id"); ok {
			teamID, err := strconv.Atoi(tValue)
			if err != nil {
				common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
				return
			}
			args["team_id"] = teamID
		}
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}
		excludeTeamIDs := []int{}
		teamIDs, err := svc.GetUnauthorizedTeamIDs(svc.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.CHECK_SCOPE_TEAMS_FAIL, err.Error())
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetDomains(db, excludeTeamIDs, args)
		common.JsonResponse(c, data, err)
	})
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

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}

		// TODO(kangxiang)
		userInfo := svc.GetUserInfo(c)
		// err = svc.IsAddPermitted(cfg.FPermit, userInfo, domainCreate.TeamID)
		// if err != nil {
		// 	common.BadRequestResponse(c, httpcommon.CHECK_SCOPE_TEAMS_FAIL, err.Error())
		// }
		//create with the user id in the header
		data, err := resource.CreateDomain(domainCreate, userInfo, db, cfg)
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

		// transfer json format to map
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}

		data, err := resource.UpdateDomain(lcuuid, patchMap, svc.GetUserInfo(c), cfg, db)
		common.JsonResponse(c, data, err)
	})
}

func deleteDomainByNameOrUUID(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}

		nameOrUUID := c.Param("name-or-uuid")
		data, err := resource.DeleteDomainByNameOrUUID(nameOrUUID, db, svc.GetUserInfo(c), cfg)
		common.JsonResponse(c, data, err)
	})
}

func deleteDomainByName(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
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
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}
		data, err := resource.DeleteDomainByNameOrUUID(name, db, svc.GetUserInfo(c), cfg)
		common.JsonResponse(c, data, err)
	})
}

func getSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]interface{})
		args["lcuuid"] = c.Param("lcuuid")
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}
		excludeTeamIDs := []int{}
		teamIDs, err := svc.GetUnauthorizedTeamIDs(svc.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.CHECK_SCOPE_TEAMS_FAIL, err.Error())
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetSubDomains(db, excludeTeamIDs, args)
		common.JsonResponse(c, data, err)
	})
}

func getSubDomains(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("domain"); ok {
			args["domain"] = value
		}
		if value, ok := c.GetQuery("cluster_id"); ok {
			args["cluster_id"] = value
		}
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}
		excludeTeamIDs := []int{}
		teamIDs, err := svc.GetUnauthorizedTeamIDs(svc.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.CHECK_SCOPE_TEAMS_FAIL, err.Error())
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetSubDomains(db, excludeTeamIDs, args)
		common.JsonResponse(c, data, err)
	})
}

func createSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var subDomainCreate model.SubDomainCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&subDomainCreate, binding.JSON)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
			return
		}

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}

		data, err := resource.CreateSubDomain(subDomainCreate, db, svc.GetUserInfo(c), cfg)
		common.JsonResponse(c, data, err)
	})
}

func deleteSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}

		lcuuid := c.Param("lcuuid")
		data, err := resource.DeleteSubDomain(lcuuid, db, svc.GetUserInfo(c), cfg)
		common.JsonResponse(c, data, err)
	})
}

func updateSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var subDomainUpdate model.SubDomainUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&subDomainUpdate, binding.JSON)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.GET_ORG_DB_FAIL, err.Error())
			return
		}

		data, err := resource.UpdateSubDomain(lcuuid, db, svc.GetUserInfo(c), cfg, patchMap)
		common.JsonResponse(c, data, err)
	})
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

func GetDomainAdditionalResourceExample(c *gin.Context) {
	data, err := resource.GetDomainAdditionalResourceExample()
	common.JsonResponse(c, data, err)
}

func updateDomainAddtionalResourceAdvanced(c *gin.Context) {
	data := &model.AdditionalResource{}
	err := c.ShouldBindBodyWith(&data, binding.YAML)
	if err == nil || err == io.EOF {
		if err = resource.ApplyDomainAddtionalResource(*data); err != nil {
			common.JsonResponse(c, httpcommon.SERVER_ERROR, err)
			return
		}
		d, err := resource.GetDomainAdditionalResource("", "")
		if err != nil {
			common.JsonResponse(c, httpcommon.SERVER_ERROR, err)
			return
		}
		b, err := yaml.Marshal(d)
		if err != nil {
			common.JsonResponse(c, httpcommon.SERVER_ERROR, err)
			return
		}
		common.JsonResponse(c, string(b), err)
	} else {
		common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}
}

func getDomainAddtionalResourceAdvanced(c *gin.Context) {
	d, err := resource.GetDomainAdditionalResource("", "")
	if err != nil {
		common.JsonResponse(c, httpcommon.SERVER_ERROR, err)
		return
	}
	b, err := yaml.Marshal(d)
	if err != nil {
		common.JsonResponse(c, httpcommon.SERVER_ERROR, err)
		return
	}
	common.JsonResponse(c, string(b), err)
}
