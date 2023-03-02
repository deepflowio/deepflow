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
	"github.com/deepflowio/deepflow/server/profile/common"
	"github.com/deepflowio/deepflow/server/profile/service"
	//"github.com/k0kubun/pp"
)

func ProfileRouter(e *gin.Engine) {
	e.POST("/v1/profile/ProfileTracing", profileTracing())

}

func profileTracing() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.ProfileParams{}
		args.Context = c.Request.Context()
		json := make(map[string]interface{})
		c.BindJSON(&json)
		args.DB, _ = json["db"].(string)
		args.Sql, _ = json["sql"].(string)
		args.Debug, _ = json["debug"].(string)
		query_uuid := uuid.New()
		args.QueryUUID = query_uuid.String()
		result, debug, err := service.Tracing(&args)
		if err == nil && args.Debug != "true" {
			debug = nil
		}
		JsonResponse(c, result, debug, err)
	})
}
