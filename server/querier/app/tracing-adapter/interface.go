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

package tracing_adapter

import (
	"net/http"
	"sync"

	adapter_config "github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/config"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/model"
	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/service"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

var (
	log      = logging.MustGetLogger("tracing-adapter")
	pipeline []adapterPipeline
	once     sync.Once
)

type adapterPipeline struct {
	config  adapter_config.ExternalAPM
	adpater model.TraceAdapter
}

func ensureAdapterConfig() {
	if config.Cfg == nil || len(config.Cfg.ExternalAPM) == 0 {
		return
	}
	once.Do(func() {
		service.Register()
		if len(pipeline) == 0 {
			pipeline = make([]adapterPipeline, 0, len(config.Cfg.ExternalAPM))
		}
		// build external trace pipelines
		for _, apm := range config.Cfg.ExternalAPM {
			if service.Adapters[apm.Name] == nil {
				continue
			}
			// allow multiple hosts configs
			log.Debugf("load adapter configs, name: %s, addr: %s", apm.Name, apm.Addr)
			pipeline = append(pipeline, adapterPipeline{apm, service.Adapters[apm.Name]})
		}
	})
}

func GetAdaptTrace(traceID string) (*model.ExTrace, error) {
	ensureAdapterConfig()
	result := &model.ExTrace{Spans: make([]model.ExSpan, 0)}
	if pipeline == nil {
		return result, nil
	}
	for _, v := range pipeline {
		if v.adpater == nil {
			continue
		}
		r, err := v.adpater.GetTrace(traceID, &v.config)
		if err != nil {
			log.Errorf("load %s data with traceid %s gets error: %s", v.config.Name, traceID, err)
			continue
		}
		if r != nil && len(r.Spans) > 0 {
			log.Debugf("load %s data with traceid %s get %d spans", v.config.Name, traceID, len(r.Spans))
			result.Spans = append(result.Spans, r.Spans...)
		}
	}
	return result, nil
}

func TraceHandler() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		traceID := ctx.Query("traceid")
		result, err := GetAdaptTrace(traceID)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, model.ExTraceResponse{Error: err.Error(), Status: common.FAIL, Data: nil})
			return
		}
		ctx.JSON(http.StatusOK, model.ExTraceResponse{Status: common.SUCCESS, Data: result})
	})
}
