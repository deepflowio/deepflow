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
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	//"github.com/k0kubun/pp"
	"io/ioutil"

	//logging "github.com/op/go-logging"
	//"fmt"
	"github.com/deepflowys/deepflow/server/querier/common"
	"github.com/deepflowys/deepflow/server/querier/service"
	"github.com/golang/protobuf/jsonpb"
	//"github.com/golang/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	//"github.com/grafana/tempo/pkg/tempopb"
	"github.com/deepflowys/deepflow/server/querier/tempo"
	"github.com/golang/protobuf/proto"
	//"github.com/k0kubun/pp"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())

	// api router for prometheus
	e.POST("/api/v1/prom/read", promReader())

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
		args.DataSource = c.PostForm("datasource")
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

func tempoTagValuesReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.TempoParams{
			TagName: c.Param("tagName"),
			Context: c.Request.Context(),
		}
		result, _, err := tempo.ShowTagValues(&args)
		if err != nil {
			c.JSON(500, err)
			return
		}
		c.JSON(200, result)
	})
}

func tempoTagsReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.TempoParams{
			Context: c.Request.Context(),
		}
		result, _, err := tempo.ShowTags(&args)
		if err != nil {
			c.JSON(500, err)
			return
		}
		c.JSON(200, result)
	})
}

func tempoSearchReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.TempoParams{
			MinDuration: c.Query("minDuration"),
			MaxDuration: c.Query("maxDuration"),
			Limit:       c.Query("limit"),
			StartTime:   c.Query("start"),
			EndTime:     c.Query("end"),
			Debug:       c.Query("debug"),
			Context:     c.Request.Context(),
		}
		args.SetFilters(c.Query("tags"))
		result, _, err := tempo.TraceSearch(&args)
		if err != nil {
			c.JSON(500, err)
			return
		}
		c.JSON(200, result)
	})
}

func tempoTraceReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.TempoParams{
			TraceId:   c.Param("traceId"),
			StartTime: c.Query("start"),
			EndTime:   c.Query("end"),
			Context:   c.Request.Context(),
		}
		resp, err := tempo.FindTraceByTraceID(&args)
		if err != nil {
			// fmt.Println(err)
			c.JSON(500, err)
			return
		}
		// record not found here, but continue on so we can marshal metrics
		// to the body
		if resp == nil || len(resp.Batches) == 0 {
			// fmt.Println(err)
			c.JSON(404, err)
			return
		}
		// fmt.Println(c.Request.Header.Get("Accept"))
		if c.Request.Header.Get("Accept") == "application/protobuf" {
			//span.SetTag("contentType", api.HeaderAcceptProtobuf)
			// pp.Println(resp)
			b, err := proto.Marshal(resp)
			if err != nil {
				c.JSON(500, err)
				return
			}
			//w.Header().Set(api.HeaderContentType, api.HeaderAcceptProtobuf)
			c.Writer.Header().Set("Content-Type", "application/protobuf")
			c.Writer.Write(b)
			return
		}

		marshaller := &jsonpb.Marshaler{}
		jsonData, err := marshaller.MarshalToString(resp)
		if err != nil {
			c.JSON(500, err)
			return
		}
		var result map[string]interface{}
		json.Unmarshal([]byte(jsonData), &result)
		c.JSON(200, result)
	})
}

func tempoEcho() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Writer.Write([]byte("echo"))
	})
}
