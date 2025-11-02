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
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/config"
	metadbcfg "github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

type ORGData struct {
	mysqlCfg metadbcfg.Config
	cfg      *config.ControllerConfig
}

func NewDatabase(cfg *config.ControllerConfig) *ORGData {
	return &ORGData{
		mysqlCfg: cfg.MetadbCfg,
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
		response.JSON(c, response.SetOptStatus(httpcommon.INVALID_POST_DATA), response.SetError(err))
		return
	}

	resp, err := service.CreateORGData(body, d.mysqlCfg)
	response.JSON(c, response.SetData(map[string]interface{}{"DATABASE": resp}), response.SetError(err))
}

func (d *ORGData) Delete(c *gin.Context) {
	orgID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		response.JSON(c, response.SetOptStatus(httpcommon.INVALID_POST_DATA), response.SetError(err))
		return
	}
	err = service.DeleteORGData(orgID, d.mysqlCfg)
	response.JSON(c, response.SetError(err))
}

func (d *ORGData) DeleteNonRealTime(c *gin.Context) {
	orgIDs, ok := c.GetQueryArray("org_id")
	if !ok {
		response.JSON(c, response.SetOptStatus(httpcommon.INVALID_POST_DATA), response.SetError(fmt.Errorf("org_id is required")))
		return
	}
	ints := make([]int, 0, len(orgIDs))
	for _, id := range orgIDs {
		i, err := strconv.Atoi(id)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_POST_DATA), response.SetError(err))
			return
		}
		ints = append(ints, i)
	}
	err := service.DeleteORGDataNonRealTime(ints)
	response.JSON(c, response.SetError(err))
}

func (d *ORGData) Get(c *gin.Context) {
	data, err := service.GetORGData(d.cfg)
	response.JSON(c, response.SetData(data), response.SetError(err))
}

func (d *ORGData) AllocORGID(c *gin.Context) {
	data, err := service.AllocORGID()
	response.JSON(c, response.SetData(data), response.SetError(err))
}
