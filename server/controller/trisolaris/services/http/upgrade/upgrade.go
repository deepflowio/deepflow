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

package upgrade

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	models "github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/trisolaris"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/dbmgr"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http/common"
)

var log = logging.MustGetLogger("trisolaris/upgrade")

func init() {
	http.Register(NewUpgradeService())
}

type UpgradeService struct{}

func NewUpgradeService() *UpgradeService {
	return &UpgradeService{}
}

type Version struct {
	Revision string `json:"REVISION" binding:"required"`
}

func Upgrade(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	if lcuuid == "" {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not find lcuuid param"))
		return
	}
	version := Version{}
	err := c.BindJSON(&version)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("%s", err)))
		return
	}
	vtap, err := dbmgr.DBMgr[models.VTap](trisolaris.GetDB()).GetFromLcuuid(lcuuid)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("%s", err)))
		return
	}
	key := vtap.CtrlIP + "-" + vtap.CtrlMac
	vTapCache := trisolaris.GetGVTapInfo().GetVTapCache(key)
	if vTapCache == nil {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not found vtap cache"))
		return
	}
	vTapCache.UpdateUpgradeRevision(version.Revision)
	log.Infof("%+v", version)
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*UpgradeService) Register(mux *gin.Engine) {
	mux.PATCH("v1/deepflow/vtaps/:lcuuid/", Upgrade)
}
