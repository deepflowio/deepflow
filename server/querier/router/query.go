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
	// "github.com/k0kubun/pp"
	//logging "github.com/op/go-logging"
	"github.com/deepflowys/deepflow/server/querier/service"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())
}

func executeQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]string)
		args["debug"] = c.Query("debug")
		args["query_uuid"] = c.Query("query_uuid")
		if args["query_uuid"] == "" {
			query_uuid := uuid.New()
			args["query_uuid"] = query_uuid.String()
		}
		args["db"] = c.PostForm("db")
		args["sql"] = c.PostForm("sql")
		args["datasource"] = c.PostForm("datasource")
		if args["sql"] == "" && args["db"] == "" {
			json := make(map[string]interface{})
			c.BindJSON(&json)
			args["db"], _ = json["db"].(string)
			args["sql"], _ = json["sql"].(string)
		}
		result, debug, err := service.Execute(args)
		if err == nil && args["debug"] != "true" {
			debug = nil
		}
		JsonResponse(c, result, debug, err)
	})
}
