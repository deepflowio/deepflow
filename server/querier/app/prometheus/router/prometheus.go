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
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/service"
)

const _STATUS_FAIL = "fail"

func adaptPromQuery(svc *service.PrometheusService, router string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var result *model.PromQueryResponse
		var err error

		if router == "label" {
			labelQueryArgs := model.PromMetaParams{
				LabelName: c.Request.FormValue("query"),
				StartTime: c.Request.FormValue("time_start"),
				EndTime:   c.Request.FormValue("time_end"),
				Context:   c.Request.Context(),
			}
			result, err = svc.PromLabelValuesService(&labelQueryArgs, c.Request.Context())
		} else {
			args := model.PromQueryParams{
				StartTime: c.Request.FormValue("time_start"),
				EndTime:   c.Request.FormValue("time_end"),
				Slimit:    c.Request.FormValue("SLIMIT"),
				Context:   c.Request.Context(),
			}
			query := c.Request.FormValue("query")
			debug := c.Request.FormValue("debug")
			args.Debug, _ = strconv.ParseBool(debug)

			switch router {
			case "query_range":
				args.Promql = query
				args.Step = c.Request.FormValue("interval")
				result, err = svc.PromRangeQueryService(&args, c.Request.Context())
			case "query":
				args.Promql = query
				result, err = svc.PromInstantQueryService(&args, c.Request.Context())
			case "series":
				args.Matchers = []string{query}
				ctx := context.WithValue(c.Request.Context(), service.CtxKeyShowTag{}, true)
				result, err = svc.PromSeriesQueryService(&args, ctx)
			}
		}
		if err != nil {
			c.JSON(500, svc.PromQLAdapter(&model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL}))
			return
		}
		c.JSON(200, svc.PromQLAdapter(result))
	})
}

// PromQL Query API
func promQuery(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromQueryParams{}
		args.Context = c.Request.Context()
		args.Promql = c.Request.FormValue("query")

		// query time range will be fixed after promQL parsed, use ReadHints instead
		// ref: https://github.com/prometheus/prometheus/blob/main/prompb/types.proto#L157
		args.StartTime = c.Request.FormValue("time")
		args.EndTime = c.Request.FormValue("time")
		args.Slimit = c.Request.FormValue("slimit")
		debug := c.Request.FormValue("debug")
		args.Debug, _ = strconv.ParseBool(debug)
		result, err := svc.PromInstantQueryService(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
		}
		c.JSON(200, result)
	})
}

// PromQL Range Query API
func promQueryRange(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromQueryParams{}
		args.Context = c.Request.Context()
		args.Promql = c.Request.FormValue("query")
		args.StartTime = c.Request.FormValue("start")
		args.EndTime = c.Request.FormValue("end")
		args.Step = c.Request.FormValue("step")
		args.Slimit = c.Request.FormValue("slimit")
		debug := c.Request.FormValue("debug")
		args.Debug, _ = strconv.ParseBool(debug)

		result, err := svc.PromRangeQueryService(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
		}
		//pp.Println(result)
		c.JSON(200, result)
	})
}

// RemoteRead API
func promReader(svc *service.PrometheusService) gin.HandlerFunc {
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
		resp, err := svc.PromRemoteReadService(&req, c.Request.Context())
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

func promTagValuesReader(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromMetaParams{
			LabelName: c.Param("labelName"),
			StartTime: c.Request.FormValue("start"),
			EndTime:   c.Request.FormValue("end"),
			Context:   c.Request.Context(),
		}
		result, err := svc.PromLabelValuesService(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
			return
		}
		c.JSON(200, result)
	})
}

func promSeriesReader(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := model.PromQueryParams{
			StartTime: c.Request.FormValue("start"),
			EndTime:   c.Request.FormValue("end"),
			Matchers:  c.Request.Form["match[]"],
			Context:   c.Request.Context(),
		}
		// should show tags when get `Series`
		ctx := context.WithValue(c.Request.Context(), service.CtxKeyShowTag{}, true)
		result, err := svc.PromSeriesQueryService(&args, ctx)
		if err != nil {
			c.JSON(500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL})
			return
		}
		c.JSON(200, result)
	})
}

func promQLAnalysis(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		metric := c.Query("metric")
		targets := c.Query("target")
		apps := c.Query("app")
		from := c.Query("from")
		to := c.Query("to")

		var targetLabels, appLabels []string
		if targets != "" {
			targetLabels = strings.Split(targets, ",")
		}
		if apps != "" {
			appLabels = strings.Split(apps, ",")
		}

		result, err := svc.PromQLAnalysis(c, metric, targetLabels, appLabels, from, to)
		if err != nil {
			c.JSON(500, result)
			return
		}
		c.JSON(200, result)
	})
}
