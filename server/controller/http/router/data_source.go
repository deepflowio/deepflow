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
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func DataSourceRouter(e *gin.Engine, cfg *config.ControllerConfig) {
	e.GET("/v1/data-sources/:lcuuid/", getDataSource)
	e.GET("/v1/data-sources/", getDataSources)
	e.POST("/v1/data-sources/", createDataSource(cfg))
	e.PATCH("/v1/data-sources/:lcuuid/", updateDataSource(cfg))
	e.DELETE("/v1/data-sources/:lcuuid/", deleteDataSource(cfg))
}

func getDataSource(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetDataSources(args)
	JsonResponse(c, data, err)
}

func getDataSources(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("type"); ok {
		args["type"] = value
	}
	if value, ok := c.GetQuery("name"); ok {
		args["name"] = value
	}
	data, err := service.GetDataSources(args)
	JsonResponse(c, data, err)
}

func createDataSource(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var dataSourceCreate model.DataSourceCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&dataSourceCreate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}

		data, err := service.CreateDataSource(dataSourceCreate, cfg)
		JsonResponse(c, data, err)
	})
}

func updateDataSource(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var dataSourceUpdate model.DataSourceUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&dataSourceUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}

		lcuuid := c.Param("lcuuid")
		data, err := service.UpdateDataSource(lcuuid, dataSourceUpdate, cfg)
		JsonResponse(c, data, err)
	})
}

func deleteDataSource(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error

		lcuuid := c.Param("lcuuid")
		data, err := service.DeleteDataSource(lcuuid, cfg)
		JsonResponse(c, data, err)
	})
}
