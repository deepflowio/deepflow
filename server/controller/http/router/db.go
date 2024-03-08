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
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/config"
	mysqlcfg "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

type Database struct {
	mysqlCfg mysqlcfg.MySqlConfig
}

func NewDatabase(cfg *config.ControllerConfig) *Database {
	return &Database{
		mysqlCfg: cfg.MySqlCfg,
	}
}

func (d *Database) RegisterTo(e *gin.Engine) {
	e.POST("/v1/databases/", d.Create)
	e.DELETE("/v1/databases/:organization-id/", d.Delete)
}

func (d *Database) Create(c *gin.Context) {
	var err error
	var body model.DatabaseCreate
	err = c.ShouldBindBodyWith(&body, binding.JSON)
	if err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_POST_DATA, err.Error())
		return
	}

	resp, err := service.CreateDatabase(body, d.mysqlCfg)
	common.JsonResponse(c, map[string]interface{}{"DATABASE": resp}, err)
}

func (d *Database) Delete(c *gin.Context) {
	oID := c.Param("organization-id")
	err := service.DeleteDatabase(oID, d.mysqlCfg)
	common.JsonResponse(c, nil, err)
}
