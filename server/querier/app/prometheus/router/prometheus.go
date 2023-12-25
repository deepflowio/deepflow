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
	"context"
	"io"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/service"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
)

const _STATUS_FAIL = "fail"
const _STATUS_SUCCESS = "success"

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
		slimit := c.Request.FormValue("slimit")
		debug := c.Request.FormValue("debug")
		offloading := c.Request.FormValue("operator-offloading")
		setRouterArgs(slimit, &args.Slimit, config.Cfg.Prometheus.SeriesLimit, strconv.Atoi)
		setRouterArgs(debug, &args.Debug, config.Cfg.Prometheus.RequestQueryWithDebug, strconv.ParseBool)
		setRouterArgs(offloading, &args.Offloading, config.Cfg.Prometheus.OperatorOffloading, strconv.ParseBool)

		result, err := svc.PromInstantQueryService(&args, c.Request.Context())
		if err != nil {
			code, obj := handleError(err)
			c.JSON(code, obj)
		} else {
			c.JSON(200, result)
		}
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
		slimit := c.Request.FormValue("slimit")
		debug := c.Request.FormValue("debug")
		offloading := c.Request.FormValue("operator-offloading")
		setRouterArgs(slimit, &args.Slimit, config.Cfg.Prometheus.SeriesLimit, strconv.Atoi)
		setRouterArgs(debug, &args.Debug, config.Cfg.Prometheus.RequestQueryWithDebug, strconv.ParseBool)
		setRouterArgs(offloading, &args.Offloading, config.Cfg.Prometheus.OperatorOffloading, strconv.ParseBool)

		result, err := svc.PromRangeQueryService(&args, c.Request.Context())
		if err != nil {
			code, obj := handleError(err)
			c.JSON(code, obj)
		} else {
			c.JSON(200, result)
		}
	})
}

// RemoteRead API
func promReader(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		compressed, _ := io.ReadAll(c.Request.Body)
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
		// configure remote read like: /api/v1/prom/read?operator-offloading=true
		offloading := c.Request.FormValue("operator-offloading")
		var offloadingArgs bool
		setRouterArgs(offloading, &offloadingArgs, config.Cfg.Prometheus.OperatorOffloading, strconv.ParseBool)
		resp, err := svc.PromRemoteReadService(&req, c.Request.Context(), offloadingArgs)
		if err != nil {
			code, _ := handleError(err)
			// remote read use different response, not use `obj`, otherwise it will cause decode response error
			if code == 200 {
				err = nil
			}
			c.JSON(code, err)
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
		debug := c.Request.FormValue("debug")
		offloading := c.Request.FormValue("operator-offloading")
		setRouterArgs(debug, &args.Debug, config.Cfg.Prometheus.RequestQueryWithDebug, strconv.ParseBool)
		setRouterArgs(offloading, &args.Offloading, config.Cfg.Prometheus.OperatorOffloading, strconv.ParseBool)
		// should show tags when get `Series`
		ctx := context.WithValue(c.Request.Context(), service.CtxKeyShowTag{}, true)
		result, err := svc.PromSeriesQueryService(&args, ctx)
		if err != nil {
			code, obj := handleError(err)
			c.JSON(code, obj)
		} else {
			c.JSON(200, result)
		}
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

func promQLParse(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		query := c.Query("query")
		result, err := svc.PromQLParse(query)
		if err != nil {
			c.JSON(500, result)
			return
		}
		c.JSON(200, result)
	})
}

func promQLAddFilters(svc *service.PrometheusService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		query := c.Query("query")
		filters, ok := c.GetQueryMap("filter")
		if !ok {
			// return query itself
			c.JSON(200, &model.PromQueryWrapper{OptStatus: _STATUS_SUCCESS, Data: []map[string]interface{}{{"query": query}}})
			return
		}
		result, err := svc.PromQLParseFilter(query, filters)
		if err != nil {
			c.JSON(500, result)
			return
		}
		c.JSON(200, result)
	})
}

// handle special errors
// only for `RESOURCE_NOT_FOUND` error, it means query non-existence metrics, it should return 200 with empty result
// but in querier, it will still cause a `RESOURCE_NOT_FOUND` to log error
func handleError(err error) (code int, obj any) {
	if err == nil {
		return 200, nil
	}
	if tErr := getInnerError(err); tErr != nil {
		switch t := tErr.(type) {
		case *common.ServiceError:
			if t.Status == common.RESOURCE_NOT_FOUND {
				return 200, &model.PromQueryResponse{
					Status: _STATUS_SUCCESS,
					Data:   &model.PromQueryData{ResultType: parser.ValueTypeVector, Result: promql.Vector{}},
				}
			}
		}
	}
	return 500, &model.PromQueryResponse{Error: err.Error(), Status: _STATUS_FAIL}
}

func getInnerError(err error) error {
	for {
		innerError := errors.Unwrap(err)
		if innerError == nil {
			return err
		}
		err = innerError
	}
}

// set args from router query or config
func setRouterArgs[T any](flag string, target *T, defaultValue T, parser func(string) (T, error)) {
	var err error
	if flag != "" && parser != nil {
		*target, err = parser(flag)
		if err != nil {
			*target = defaultValue
		}
	} else {
		*target = defaultValue
	}
}
