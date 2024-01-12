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
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	servicecommon "github.com/deepflowio/deepflow/server/controller/http/service/common"
)

var log = logging.MustGetLogger("router")

const OK = "ok"

var curStage string
var curStageStartedAt time.Time

type Health struct{}

func NewHealth() *Health {
	return new(Health)
}

func (s *Health) RegisterTo(e *gin.Engine) {
	e.GET("/v1/health/", func(c *gin.Context) {
		if curStage == OK {
			JsonResponse(c, make(map[string]string), nil)
		} else {
			msg := fmt.Sprintf("server is in stage: %s now, time cost: %v", curStage, time.Since(curStageStartedAt))
			log.Errorf(msg)
			JsonResponse(
				c, make(map[string]string),
				servicecommon.NewError(httpcommon.SERVICE_UNAVAILABLE, msg),
			)
		}
	})
}

func SetInitStageForHealthChecker(s string) {
	if curStage != "" {
		log.Infof("stage: %s, time cost: %v", curStage, time.Since(curStageStartedAt))
	}
	curStage = s
	curStageStartedAt = time.Now()
}
