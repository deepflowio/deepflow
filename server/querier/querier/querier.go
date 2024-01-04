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

package querier

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/stats"
	prometheus_router "github.com/deepflowio/deepflow/server/querier/app/prometheus/router"
	tracing_adapter "github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/router"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	profile_router "github.com/deepflowio/deepflow/server/querier/profile/router"
	"github.com/deepflowio/deepflow/server/querier/router"
	"github.com/deepflowio/deepflow/server/querier/statsd"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

var log = logging.MustGetLogger("querier")

func Start(configPath, serverLogFile string) {
	ServerCfg := config.DefaultConfig()
	ServerCfg.Load(configPath)
	config.Cfg = &ServerCfg.QuerierConfig
	config.TraceConfig = &ServerCfg.TraceIdWithIndex
	cfg := ServerCfg.QuerierConfig
	bytes, _ := yaml.Marshal(cfg)
	log.Info("==================== Launching DeepFlow-Server-Querier ====================")
	log.Infof("querier config:\n%s", string(bytes))

	// engine加载数据库tag/metric等信息
	err := Load()
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}

	// prometheus dict cache
	go clickhouse.GeneratePrometheusMap()

	// statsd
	statsd.QuerierCounter = statsd.NewCounter()
	statsd.RegisterCountableForIngester("querier_count", statsd.QuerierCounter)

	// init opentelemetry
	if cfg.OtelEndpoint != "" {
		log.Infof("init opentelemetry: otel-endpoint(%s)", cfg.OtelEndpoint)
		initTraceProvider(cfg.OtelEndpoint)
	}

	ginLogFile, _ := os.OpenFile(serverLogFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	gin.DefaultWriter = io.MultiWriter(ginLogFile, os.Stdout)

	// 注册router
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(otelgin.Middleware("gin-web-server"))
	r.Use(gin.LoggerWithFormatter(logger.GinLogFormat))
	r.Use(StatdHandle())
	r.Use(ErrHandle())
	router.QueryRouter(r)
	profile_router.ProfileRouter(r, &cfg)
	prometheus_router.PrometheusRouter(r)
	tracing_adapter.TracingAdapterRouter(r)
	registerRouterCounter(r.Routes())
	// TODO: 增加router
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
		statsd.QuerierCounter.Close()
		os.Exit(0)
	}
}

func registerRouterCounter(routers gin.RoutesInfo) {
	statsd.ApiCounters = make(map[string]*statsd.ApiCounter, len(routers))
	for _, v := range routers {
		newCounter := statsd.NewApiCounter()
		statsd.ApiCounters[v.Method+v.Path] = newCounter
		statsd.RegisterCountableForIngester("querier_api_count", newCounter, stats.OptionStatTags{
			"method": v.Method,
			"path":   v.Path,
		})
	}
}

func ErrHandle() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		defer func() {
			ip := c.ClientIP()          //请求ip
			method := c.Request.Method  // Method
			url := c.Request.RequestURI // url
			db := c.PostForm("db")
			sql := c.PostForm("sql")
			ds := c.PostForm("datasource")
			if err := recover(); err != nil {
				// 记录一个错误的日志
				log.Errorf("%13v | %15s | %s | %s | %s | %s | %s |",
					time.Since(startTime), //执行时间
					ip,
					method,
					url,
					db,
					sql,
					ds,
				)
				log.Error(err)
				// 堆栈信息
				var buf [4096]byte
				n := runtime.Stack(buf[:], false)
				log.Error(string(buf[:n]))
				router.BadRequestResponse(c, common.SERVER_ERROR, fmt.Sprintf("%v", err))
				c.JSON(500, err)
				return
			}
		}()
		c.Next()
	}
}

func StatdHandle() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		key := c.Request.Method + c.Request.URL.Path
		c.Next()
		statsd.QuerierCounter.WriteApi(
			&statsd.ClickhouseCounter{
				ApiTime: uint64(time.Since(startTime)),
			},
		)
		// counters for per api
		if counter, ok := statsd.ApiCounters[key]; ok {
			counter.Write(
				&statsd.ApiStats{
					ApiTime: uint64(time.Since(startTime)),
				},
			)
		}
	}
}
