/*
 * Copyright (c) 2023 Yunshan Networks
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
	"context"
	"io/ioutil"

	"github.com/gin-gonic/gin"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"

	//logging "github.com/op/go-logging"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/service"
)

const _STATUS_FAIL = "fail"

// PromQL Query API
func promQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromQueryParams{}
		args.Context = c.Request.Context()
		args.Promql = c.Request.FormValue("query")

		// query time range will be fixed after promQL parsed, use ReadHints instead
		// ref: https://github.com/prometheus/prometheus/blob/main/prompb/types.proto#L157
		args.StartTime = c.Request.FormValue("time")
		args.EndTime = c.Request.FormValue("time")
		result, err := service.PromInstantQueryService(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
		}
		c.JSON(200, result)
	})
}

// PromQL Range Query API
func promQueryRange() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromQueryParams{}
		args.Context = c.Request.Context()
		args.Promql = c.Request.FormValue("query")
		args.StartTime = c.Request.FormValue("start")
		args.EndTime = c.Request.FormValue("end")
		args.Step = c.Request.FormValue("step")
		//pp.Println(c.Request.Header.Get("Accept"))
		//pp.Println(args.Promql)

		result, err := service.PromRangeQueryService(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
		}
		//pp.Println(result)
		c.JSON(200, result)
	})
}

// RemoteRead API
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
		resp, err := service.PromRemoteReadService(&req, c.Request.Context())
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

func promTagValuesReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromMetaParams{
			LabelName: c.Param("labelName"),
			StartTime: c.Request.FormValue("start"),
			EndTime:   c.Request.FormValue("end"),
			Context:   c.Request.Context(),
		}
		result, err := service.PromLabelValuesService(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
			return
		}
		c.JSON(200, result)
	})
}

func promSeriesReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromQueryParams{
			StartTime: c.Request.FormValue("start"),
			EndTime:   c.Request.FormValue("end"),
			Matchers:  c.Request.Form["match[]"],
			Context:   c.Request.Context(),
		}
		// should show tags when get `Series`
		ctx := context.WithValue(c.Request.Context(), service.CtxKeyShowTag{}, true)
		result, err := service.PromSeriesQueryService(&args, ctx)
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
			return
		}
		c.JSON(200, result)
	})
}
