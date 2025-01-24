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

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/http/service/vtap"
)

type VTapInterface struct {
	cfg ctrlrcommon.FPermit
}

func NewVTapInterface(cfg ctrlrcommon.FPermit) *VTapInterface {
	return &VTapInterface{cfg: cfg}
}

func (v *VTapInterface) RegisterTo(e *gin.Engine) {
	e.GET("/v1/vtap-interfaces/", v.getVTapInterfaces())
}

func (v *VTapInterface) getVTapInterfaces() gin.HandlerFunc {
	return func(c *gin.Context) {
		args := make(map[string]interface{})
		if value, ok := c.GetQuery("team_id"); ok {
			args["team_id"] = value
		}
		if value, ok := c.GetQuery("user_id"); ok {
			args["user_id"] = value
		}
		data, err := vtap.NewVTapInterface(v.cfg, httpcommon.GetUserInfo(c)).Get(args)
		response.JSON(c, response.SetData(data), response.SetError(err))
	}
}
