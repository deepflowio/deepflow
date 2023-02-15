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
	"github.com/google/uuid"
	//"github.com/k0kubun/pp"

	//logging "github.com/op/go-logging"
	//"fmt"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/service"
	//"github.com/k0kubun/pp"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())

	// api router for prometheus
	e.POST("/api/v1/prom/read", promReader())
	e.GET("/prom/api/v1/query", promQuery())
	e.GET("/prom/api/v1/query_range", promQueryRange())
	e.POST("/prom/api/v1/query", promQuery())
	e.POST("/prom/api/v1/query_range", promQueryRange())
	e.GET("/prom/api/v1/label/:labelName/values", promTagValuesReader())
	e.GET("/prom/api/v1/series", promSeriesReader())
	e.POST("/prom/api/v1/series", promSeriesReader())

	// api router for tempo
	e.GET("/api/traces/:traceId", tempoTraceReader())
	e.GET("/api/echo", tempoEcho())
	e.GET("/api/search/tags", tempoTagsReader())
	e.GET("/api/search/tag/:tagName/values", tempoTagValuesReader())
	e.GET("/api/search", tempoSearchReader())

}

func executeQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.QuerierParams{}
		args.Context = c.Request.Context()
		args.Debug = c.Query("debug")
		args.QueryUUID = c.Query("query_uuid")
		if args.QueryUUID == "" {
			query_uuid := uuid.New()
			args.QueryUUID = query_uuid.String()
		}
		args.DB = c.PostForm("db")
		args.Sql = c.PostForm("sql")
		args.DataSource = c.PostForm("data_precision")
		if args.Sql == "" && args.DB == "" {
			json := make(map[string]interface{})
			c.BindJSON(&json)
			args.DB, _ = json["db"].(string)
			args.Sql, _ = json["sql"].(string)
		}
		result, debug, err := service.Execute(&args)
		if err == nil && args.Debug != "true" {
			debug = nil
		}
		JsonResponse(c, result, debug, err)
	})
}
