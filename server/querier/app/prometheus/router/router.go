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
	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/querier/app/prometheus/router/packet_adapter"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/service"
	"github.com/deepflowio/deepflow/server/querier/config"
)

func PrometheusRouter(e *gin.Engine) {
	// only one instance during server lifetime
	prometheusService := service.NewPrometheusService()
	// Both SetRate and Acquire are expanded by 1000 times, making it suitable for small QPS scenarios.
	prometheusService.QPSLeakyBucket.Init(uint64(config.Cfg.Prometheus.QPSLimit * 1000))

	// api router for prometheus
	e.POST("/api/v1/prom/read", Limiter(prometheusService.QPSLeakyBucket), promReader(prometheusService))

	promGroup := e.Group("/prom")
	// prometheus query rate limit
	promGroup.Use(Limiter(prometheusService.QPSLeakyBucket))
	{
		promGroup.GET("/api/v1/query", promQuery(prometheusService))
		promGroup.GET("/api/v1/query_range", promQueryRange(prometheusService))
		promGroup.POST("/api/v1/query", promQuery(prometheusService))
		promGroup.POST("/api/v1/query_range", promQueryRange(prometheusService))
		promGroup.GET("/api/v1/series", promSeriesReader(prometheusService))
		promGroup.POST("/api/v1/series", promSeriesReader(prometheusService))
		promGroup.GET("/api/v1/label/:labelName/values", promTagValuesReader(prometheusService))

		// not use "/prom/api/v1/adapter/:name", suitable for map[rouer key]counter in statsd
		for _, v := range []string{"label", "query_range", "query", "series"} {
			promGroup.POST("/api/v1/adapter/"+v, packet_adapter.AdaptPromQuery(prometheusService, v))
			promGroup.GET("/api/v1/adapter/"+v, packet_adapter.AdaptPromQuery(prometheusService, v))
		}
	}

	// not using rate-limit, cause it's low-frequency of request-calling
	e.GET("/prom/api/v1/analysis", promQLAnalysis(prometheusService))
	e.GET("/prom/api/v1/parse", promQLParse(prometheusService))
	e.GET("/prom/api/v1/addfilter", promQLAddFilters(prometheusService))
}
