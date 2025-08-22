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
	mysqlcommon "github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
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
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["user_id"] = userID
		}
		if tValue, ok := c.GetQuery("team_id"); ok {
			teamID, err := strconv.Atoi(tValue)
			if err != nil {
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["team_id"] = teamID
		}
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		excludeTeamIDs := []int{}
		teamIDs, err := httpcommon.GetUnauthorizedTeamIDs(httpcommon.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.CHECK_SCOPE_TEAMS_FAIL), response.SetError(err))
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetDomains(db, excludeTeamIDs, args)
		response.JSON(c, response.SetData(data), response.SetError(err))
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
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["user_id"] = userID
		}
		if tValue, ok := c.GetQuery("team_id"); ok {
			teamID, err := strconv.Atoi(tValue)
			if err != nil {
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["team_id"] = teamID
		}
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		excludeTeamIDs := []int{}
		teamIDs, err := httpcommon.GetUnauthorizedTeamIDs(httpcommon.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.CHECK_SCOPE_TEAMS_FAIL), response.SetError(err))
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetDomains(db, excludeTeamIDs, args)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func createDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var domainCreate model.DomainCreate

		// message validation
		err = c.ShouldBindBodyWith(&domainCreate, binding.JSON)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_POST_DATA), response.SetError(err))
			return
		}
		if domainCreate.TeamID == 0 {
			domainCreate.TeamID = mysqlcommon.DEFAULT_TEAM_ID
		}

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}

		//create with the user id in the header
		data, err := resource.CreateDomain(domainCreate, httpcommon.GetUserInfo(c), db, cfg)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func updateDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var domainUpdate model.DomainUpdate

		// message validation
		err = c.ShouldBindBodyWith(&domainUpdate, binding.JSON)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}

		// transfer json format to map
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}

		data, err := resource.UpdateDomain(lcuuid, patchMap, httpcommon.GetUserInfo(c), cfg, db)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func deleteDomainByNameOrUUID(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}

		nameOrUUID := c.Param("name-or-uuid")
		data, err := resource.DeleteDomainByNameOrUUID(nameOrUUID, db, httpcommon.GetUserInfo(c), cfg)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func deleteDomainByName(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		rawQuery := strings.Split(c.Request.URL.RawQuery, "name=")
		if len(rawQuery) < 1 {
			response.JSON(c, response.SetError(response.ServiceError(httpcommon.PARAMETER_ILLEGAL, fmt.Sprintf("please fill in the name parameter: domains/?name={}"))))
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
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		data, err := resource.DeleteDomainByNameOrUUID(name, db, httpcommon.GetUserInfo(c), cfg)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]interface{})
		args["lcuuid"] = c.Param("lcuuid")
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		if uValue, ok := c.GetQuery("user_id"); ok {
			userID, err := strconv.Atoi(uValue)
			if err != nil {
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["user_id"] = userID
		}
		if tValue, ok := c.GetQuery("team_id"); ok {
			teamID, err := strconv.Atoi(tValue)
			if err != nil {
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["team_id"] = teamID
		}
		excludeTeamIDs := []int{}
		teamIDs, err := httpcommon.GetUnauthorizedTeamIDs(httpcommon.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.CHECK_SCOPE_TEAMS_FAIL), response.SetError(err))
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetSubDomains(db, excludeTeamIDs, args)
		response.JSON(c, response.SetData(data), response.SetError(err))
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
		if uValue, ok := c.GetQuery("user_id"); ok {
			userID, err := strconv.Atoi(uValue)
			if err != nil {
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["user_id"] = userID
		}
		if tValue, ok := c.GetQuery("team_id"); ok {
			teamID, err := strconv.Atoi(tValue)
			if err != nil {
				response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
				return
			}
			args["team_id"] = teamID
		}
		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		excludeTeamIDs := []int{}
		teamIDs, err := httpcommon.GetUnauthorizedTeamIDs(httpcommon.GetUserInfo(c), &cfg.FPermit)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.CHECK_SCOPE_TEAMS_FAIL), response.SetError(err))
			return
		}
		for k := range teamIDs {
			excludeTeamIDs = append(excludeTeamIDs, k)
		}
		data, err := resource.GetSubDomains(db, excludeTeamIDs, args)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func createSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var subDomainCreate model.SubDomainCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&subDomainCreate, binding.JSON)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_POST_DATA), response.SetError(err))
			return
		}

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}

		data, err := resource.CreateSubDomain(subDomainCreate, db, httpcommon.GetUserInfo(c), cfg)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func deleteSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}

		lcuuid := c.Param("lcuuid")
		data, err := resource.DeleteSubDomain(lcuuid, db, httpcommon.GetUserInfo(c), cfg)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func updateSubDomain(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var subDomainUpdate model.SubDomainUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&subDomainUpdate, binding.JSON)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")

		db, err := common.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}

		data, err := resource.UpdateSubDomain(lcuuid, db, httpcommon.GetUserInfo(c), cfg, patchMap)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func applyDomainAddtionalResource(c *gin.Context) {
	b, err := io.ReadAll(c.Request.Body)
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.SERVER_ERROR), response.SetError(err))
		return
	}
	err = common.CheckJSONParam(string(b), model.AdditionalResource{})
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
		return
	}

	var data model.AdditionalResource
	err = json.Unmarshal(b, &data)
	// invalidate request body
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
		return
	}

	db, err := common.GetContextOrgDB(c)
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
		return
	}

	err = resource.ApplyDomainAddtionalResource(data, db)
	response.JSON(c, response.SetError(err))
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
		response.JSON(c, response.SetError(response.ServiceError(httpcommon.PARAMETER_ILLEGAL, fmt.Sprintf("please enter resource type, resource name(%v)", resourceName))))
		return
	}

	db, err := common.GetContextOrgDB(c)
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
		return
	}

	data, err := resource.ListDomainAdditionalResource(resourceType, resourceName, db)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func GetDomainAdditionalResourceExample(c *gin.Context) {
	data, err := resource.GetDomainAdditionalResourceExample()
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func updateDomainAddtionalResourceAdvanced(c *gin.Context) {
	db, err := common.GetContextOrgDB(c)
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
		return
	}

	data := &model.AdditionalResource{}
	err = c.ShouldBindBodyWith(&data, binding.YAML)
	if err == nil || err == io.EOF {
		if err = resource.ApplyDomainAddtionalResource(*data, db); err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		d, err := resource.GetDomainAdditionalResource("", "", db)
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		b, err := yaml.Marshal(d)
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		response.JSON(c, response.SetData(string(b))) // TODO 不需要转换类型
	} else {
		response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
		return
	}
}

func getDomainAddtionalResourceAdvanced(c *gin.Context) {
	db, err := common.GetContextOrgDB(c)
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
		return
	}

	d, err := resource.GetDomainAdditionalResource("", "", db)
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	b, err := yaml.Marshal(d)
	if err != nil {
		response.JSON(c, response.SetError(err))
		return
	}
	response.JSON(c, response.SetData(string(b))) // TODO 不需要转换类型
}
