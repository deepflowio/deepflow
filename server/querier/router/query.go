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
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/service"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())

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
		args.UseQueryCache, _ = strconv.ParseBool(c.DefaultQuery("use_query_cache", "false"))
		args.QueryCacheTTL = c.Query("query_cache_ttl")
		args.QueryUUID = c.Query("query_uuid")
		args.NoPreWhere, _ = strconv.ParseBool(c.DefaultQuery("no_prewhere", "false"))
		args.ORGID = c.Request.Header.Get(common.HEADER_KEY_X_ORG_ID)
		// if no org_id in header, set default org id
		if args.ORGID == "" {
			args.ORGID = common.DEFAULT_ORG_ID
		}
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
