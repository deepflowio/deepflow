/**
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

package resource

import (
	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/config"
	dbredis "github.com/deepflowio/deepflow/server/controller/db/redis"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	httpCfg "github.com/deepflowio/deepflow/server/controller/http/config"
	"github.com/deepflowio/deepflow/server/controller/http/model"
	"github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource"
)

type DHCPPort struct {
	httpCfg    httpCfg.Config
	redisCfg   dbredis.Config
	fpermitCfg config.FPermit
}

func NewDHCPPort(hCfg httpCfg.Config, rCfg dbredis.Config, fCfg config.FPermit) *DHCPPort {
	return &DHCPPort{httpCfg: hCfg, redisCfg: rCfg, fpermitCfg: fCfg}
}

func (p *DHCPPort) RegisterTo(ge *gin.Engine) {
	ge.GET(httpcommon.PATH_DHCP_PORT, p.Get)
}

func (p *DHCPPort) Get(c *gin.Context) {
	header := NewHeaderValidator(c.Request.Header, p.fpermitCfg)
	query := NewQueryValidator[model.DHCPPortQuery](c.Request.URL.Query())
	if err := NewValidators(header, query).Validate(); err != nil {
		common.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}
	service := resource.NewDHCPPortGet(
		NewURLInfo(
			c.Request.URL.String(),
			query.structData,
		),
		header.userInfo,
		p.redisCfg,
		p.fpermitCfg,
	)
	if query.structData.RefreshCache {
		data, err := service.RefreshCache()
		common.JsonResponse(c, data, err)
	} else {
		data, err := service.Get()
		common.JsonResponse(c, data, err)
	}
}

func (p *DHCPPort) Update(c *gin.Context) {

}
