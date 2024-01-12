/**
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
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/deepflowio/deepflow/server/controller/common"
	routercommon "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/prometheus"
)

type Prometheus struct{}

func NewPrometheus() *Prometheus {
	return &Prometheus{}
}

func (p *Prometheus) RegisterTo(e *gin.Engine) {
	e.POST("/v1/prometheus-cleaner-tasks/", createPrometheusCleanTask)
}

func createPrometheusCleanTask(c *gin.Context) {
	body := make(map[string]interface{})
	err := c.ShouldBindBodyWith(&body, binding.JSON)
	log.Errorf("body: %v", body)
	if err != nil {
		log.Errorf("body: %v", err)
		routercommon.JsonResponse(c, body, err)
		return
	}

	isMaster, masterCtrlIP, httpPort, _, err := common.CheckSelfAndGetMasterControllerHostPort()
	if err != nil {
		log.Errorf("body: %v", err)
		routercommon.JsonResponse(c, body, err)
		return
	}
	if isMaster {
		expiredAt := time.Time{}
		if e, ok := body["EXPIRED_AT"]; ok {
			expiredAt, err = time.Parse(common.GO_BIRTHDAY, e.(string))
			if err != nil {
				log.Errorf("body: %v", err)
				routercommon.JsonResponse(c, body, err)
				return
			}
		}
		log.Errorf("body: %v", body)
		err = prometheus.GetCleaner().Clear(expiredAt)
	} else {
		_, err = common.CURLPerform(http.MethodPost, fmt.Sprintf("http://%s:%d/v1/prometheus-cleaner-tasks/", masterCtrlIP, httpPort), body)
		log.Errorf("body: %v", err)
	}
	routercommon.JsonResponse(c, body, err)
}
