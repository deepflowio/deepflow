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

	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

type Icon struct {
	cfg *config.ControllerConfig
}

func NewIcon(cfg *config.ControllerConfig) *Icon {
	return &Icon{cfg: cfg}
}

func (i *Icon) RegisterTo(e *gin.Engine) {
	e.GET("/v1/icons/", getIcon(i.cfg))
}

func getIcon(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetIcon(cfg)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}
