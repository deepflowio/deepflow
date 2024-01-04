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
	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/libs/datastructure"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/router/packet_adapter"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/service"
	"github.com/deepflowio/deepflow/server/querier/config"
)

func PrometheusRouter(e *gin.Engine) {
	// prometheus query rate limit
	service.QPSLeakyBucket = &datastructure.LeakyBucket{}
	// Both SetRate and Acquire are expanded by 1000 times, making it suitable for small QPS scenarios.
	service.QPSLeakyBucket.Init(uint64(config.Cfg.Prometheus.QPSLimit * 1000))

	// only one instance during server lifetime
	prometheusService := service.NewPrometheusService()

	// api router for prometheus
	e.POST("/api/v1/prom/read", promReader(prometheusService))
	e.GET("/prom/api/v1/query", promQuery(prometheusService))
	e.GET("/prom/api/v1/query_range", promQueryRange(prometheusService))
	e.POST("/prom/api/v1/query", promQuery(prometheusService))
	e.POST("/prom/api/v1/query_range", promQueryRange(prometheusService))
	e.GET("/prom/api/v1/series", promSeriesReader(prometheusService))
	e.POST("/prom/api/v1/series", promSeriesReader(prometheusService))
	e.GET("/prom/api/v1/label/:labelName/values", promTagValuesReader(prometheusService))
	e.GET("/prom/api/v1/analysis", promQLAnalysis(prometheusService))

	// not use "/prom/api/v1/adapter/:name", suitable for map[rouer key]counter in statsd
	for _, v := range []string{"label", "query_range", "query", "series"} {
		e.POST("/prom/api/v1/adapter/"+v, packet_adapter.AdaptPromQuery(prometheusService, v))
		e.GET("/prom/api/v1/adapter/"+v, packet_adapter.AdaptPromQuery(prometheusService, v))
	}

	e.GET("/prom/api/v1/parse", promQLParse(prometheusService))
	e.GET("/prom/api/v1/addfilter", promQLAddFilters(prometheusService))
}
