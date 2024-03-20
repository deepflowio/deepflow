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

package upgrade

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	. "github.com/deepflowio/deepflow/server/controller/common"
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
	ImageName string `json:"image_name" binding:"required"`
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

	vtapRrepo, err := dbmgr.DBMgr[models.VTapRepo](trisolaris.GetDB()).GetFieldsFromName(
		[]string{"rev_count", "commit_id"}, upgradeInfo.ImageName)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("%s", err)))
		return
	}
	var expectedRevision string
	if vtapRrepo.RevCount != "" && vtapRrepo.CommitID != "" {
		expectedRevision = vtapRrepo.RevCount + "-" + vtapRrepo.CommitID
	}
	if len(expectedRevision) == 0 {
		errLog := fmt.Sprintf("get vtapRepo(%s) failed RevCount=%s CommitID=%s",
			upgradeInfo.ImageName, vtapRrepo.RevCount, vtapRrepo.CommitID)
		log.Error(errLog)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, errLog))
		return
	}

	vtap, err := dbmgr.DBMgr[models.VTap](trisolaris.GetDB()).GetFromLcuuid(lcuuid)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("%s", err)))
		return
	}
	key := vtap.CtrlIP + "-" + vtap.CtrlMac
	vTapCache := trisolaris.GetGVTapInfo(DEFAULT_ORG_ID).GetVTapCache(key)
	if vTapCache == nil {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not found vtap cache"))
		return
	}
	vTapCache.UpdateUpgradeInfo(expectedRevision, upgradeInfo.ImageName)
	log.Infof("vtap(%s, %s) upgrade:(%s, %s)", vtap.Name, key, expectedRevision, upgradeInfo.ImageName)
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*UpgradeService) Register(mux *gin.Engine) {
	mux.PATCH("v1/upgrade/vtap/:lcuuid/", Upgrade)
}
