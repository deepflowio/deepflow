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
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("router")

const (
	OK = "ok"

	StageMetadbMigration = "Metadb migration"
)

var curStage string
var curStageStartedAt time.Time

type Health struct{}

func NewHealth() *Health {
	return new(Health)
}

func (s *Health) RegisterTo(e *gin.Engine) {
	e.GET("/v1/health/", func(c *gin.Context) {
		if curStage == OK {
			response.JSON(c)
		} else {
			curStageCost := time.Since(curStageStartedAt)
			msg := fmt.Sprintf("server is in stage: %s now, time cost: %v", curStage, curStageCost)
			log.Errorf(msg)
			if curStage == StageMetadbMigration && curStageCost > 30*time.Second {
				log.Warningf("Metadb migration is taking too long, please add initialDelaySeconds of server to wait for migration to complete")
			}
			response.JSON(
				c,
				response.SetError(response.ServiceError(httpcommon.SERVICE_UNAVAILABLE, msg)),
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
