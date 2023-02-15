/*
 * Copyright (c) 2022 Yunshan Networks
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

package health

import (
	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http/common"
)

func init() {
	http.Register(NewHealth())
}

func NewHealth() *HealthService {
	return &HealthService{}
}

type HealthService struct{}

func Health(c *gin.Context) {
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*HealthService) Register(mux *gin.Engine) {
	mux.GET("/v1/health/", Health)
}
