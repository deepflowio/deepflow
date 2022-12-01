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
	"io/ioutil"

	//logging "github.com/op/go-logging"
	"github.com/deepflowys/deepflow/server/querier/common"
	"github.com/deepflowys/deepflow/server/querier/service"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())
	e.POST("/api/v1/prom/read", promReader())
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

func promReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		compressed, _ := ioutil.ReadAll(c.Request.Body)
		reqBuf, err := snappy.Decode(nil, compressed)
		if err != nil {
			c.JSON(500, err)
			return
		}
		var req prompb.ReadRequest
		if err := req.Unmarshal(reqBuf); err != nil {
			c.JSON(500, err)
			return
		}
		//pp.Println(req)
		resp, err := service.PromReaderExecute(&req, c.Request.Context())
		//pp.Println(resp)
		if err != nil {
			c.JSON(500, err)
			return
		}
		data, err := resp.Marshal()
		if err != nil {
			c.JSON(500, err)
			return
		}
		compressed = snappy.Encode(nil, data)
		c.Writer.Write([]byte(compressed))
	})
}
