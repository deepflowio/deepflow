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

	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http/common"
)

var log = logging.MustGetLogger("trisolaris/upgrade")

func init() {
	http.Register(NewUpgradeService())
}

type UpgradeService struct{}

func NewUpgradeService() *UpgradeService {
	return &UpgradeService{}
}

type UpgradeInfo struct {
	ExpectedRevision string `json:"expected_revision" binding:"required"`
	UpgradePackage   string `json:"upgrade_package" binding:"required"`
}

func Upgrade(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	if lcuuid == "" {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not find lcuuid param"))
		return
	}
	upgradeInfo := UpgradeInfo{}
	err := c.BindJSON(&upgradeInfo)
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
	vTapCache.UpdateUpgradeInfo(upgradeInfo.ExpectedRevision, upgradeInfo.UpgradePackage)
	log.Infof("vtap(%s, %s) upgrade:%+v", vtap.Name, key, upgradeInfo)
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*UpgradeService) Register(mux *gin.Engine) {
	mux.PATCH("v1/upgrade/vtap/:lcuuid/", Upgrade)
}
