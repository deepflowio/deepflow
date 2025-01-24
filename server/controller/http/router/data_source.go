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
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type DataSource struct {
	cfg *config.ControllerConfig
}

func NewDataSource(cfg *config.ControllerConfig) *DataSource {
	return &DataSource{cfg: cfg}
}

func (d *DataSource) RegisterTo(e *gin.Engine) {
	e.GET("/v1/data-sources/:lcuuid/", d.getDataSource())
	e.GET("/v1/data-sources/", d.getDataSources())
	e.POST("/v1/data-sources/", d.createDataSource())
	e.PATCH("/v1/data-sources/:lcuuid/", d.updateDataSource())
	e.DELETE("/v1/data-sources/:lcuuid/", d.deleteDataSource())
}

func (d *DataSource) getDataSource() gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		args["lcuuid"] = c.Param("lcuuid")
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		dataSourceService := service.NewDataSource(httpcommon.GetUserInfo(c), d.cfg)
		data, err := dataSourceService.GetDataSources(orgID.(int), args, nil)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}

func (d *DataSource) getDataSources() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("type"); ok {
			args["type"] = value
		}
		if value, ok := c.GetQuery("name"); ok {
			args["name"] = value
		}
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		dataSourceService := service.NewDataSource(httpcommon.GetUserInfo(c), d.cfg)
		data, err := dataSourceService.GetDataSources(orgID.(int), args, &d.cfg.Spec)
		if err != nil {
			log.Error("get data source error: %s", err, logger.NewORGPrefix(orgID.(int)))
		}
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func (d *DataSource) createDataSource() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var dataSourceCreate *model.DataSourceCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&dataSourceCreate, binding.JSON)
		if dataSourceCreate != nil &&
			!(dataSourceCreate.DataTableCollection == "flow_metrics.application*" || dataSourceCreate.DataTableCollection == "flow_metrics.network*") {
			response.JSON(c, response.SetStatus(httpcommon.INVALID_PARAMETERS), response.SetDescription("tsdb type only supports flow_metrics.application* and flow_metrics.network*"))
			return
		}
		if err != nil {
			response.JSON(c, response.SetStatus(httpcommon.INVALID_PARAMETERS), response.SetDescription(err.Error()))
			return
		}

		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		dataSourceService := service.NewDataSource(httpcommon.GetUserInfo(c), d.cfg)
		data, err := dataSourceService.CreateDataSource(orgID.(int), dataSourceCreate)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func (d *DataSource) updateDataSource() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var dataSourceUpdate model.DataSourceUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&dataSourceUpdate, binding.JSON)
		if err != nil {
			response.JSON(c, response.SetStatus(httpcommon.INVALID_POST_DATA), response.SetDescription(err.Error()))
			return
		}

		lcuuid := c.Param("lcuuid")
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		dataSourceService := service.NewDataSource(httpcommon.GetUserInfo(c), d.cfg)
		data, err := dataSourceService.UpdateDataSource(orgID.(int), lcuuid, dataSourceUpdate)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func (d *DataSource) deleteDataSource() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error

		lcuuid := c.Param("lcuuid")
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		dataSourceService := service.NewDataSource(httpcommon.GetUserInfo(c), d.cfg)
		data, err := dataSourceService.DeleteDataSource(orgID.(int), lcuuid)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}
