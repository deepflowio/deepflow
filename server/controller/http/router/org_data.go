/**
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
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/config"
	metadbcfg "github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

type ORGData struct {
	mysqlCfg metadbcfg.MySqlConfig
	cfg      *config.ControllerConfig
}

func NewDatabase(cfg *config.ControllerConfig) *ORGData {
	return &ORGData{
		mysqlCfg: cfg.MySqlCfg,
		cfg:      cfg,
	}
}

func (d *ORGData) RegisterTo(e *gin.Engine) {
	e.GET("/v1/orgs/", d.Get)
	e.POST("/v1/org/", d.Create)
	e.DELETE("/v1/org/:id/", d.Delete)        // provide for real-time call when deleting an organization
	e.DELETE("/v1/org/", d.DeleteNonRealTime) // provide for non-real-time call from master controller after deleting an organization
	e.GET("/v1/alloc-org-id/", d.AllocORGID)
}

func (d *ORGData) Create(c *gin.Context) {
	var err error
	var body model.ORGDataCreate
	err = c.ShouldBindBodyWith(&body, binding.JSON)
	if err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
		return
	}

	resp, err := service.CreateORGData(body, d.mysqlCfg)
	common.JsonResponse(c, map[string]interface{}{"DATABASE": resp}, err)
}

func (d *ORGData) Delete(c *gin.Context) {
	orgID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
		return
	}
	err = service.DeleteORGData(orgID, d.mysqlCfg)
	common.JsonResponse(c, nil, err)
}

func (d *ORGData) DeleteNonRealTime(c *gin.Context) {
	orgIDs, ok := c.GetQueryArray("org_id")
	if !ok {
		common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, "org_id is required")
		return
	}
	ints := make([]int, 0, len(orgIDs))
	for _, id := range orgIDs {
		i, err := strconv.Atoi(id)
		if err != nil {
			common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
			return
		}
		ints = append(ints, i)
	}
	err := service.DeleteORGDataNonRealTime(ints)
	common.JsonResponse(c, nil, err)
}

func (d *ORGData) Get(c *gin.Context) {
	data, err := service.GetORGData(d.cfg)
	common.JsonResponse(c, data, err)
}

func (d *ORGData) AllocORGID(c *gin.Context) {
	data, err := service.AllocORGID()
	common.JsonResponse(c, data, err)
}
