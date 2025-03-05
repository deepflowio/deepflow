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

	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	models "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("trisolaris.upgrade")

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
	var err error
	lcuuid := c.Param("lcuuid")
	if lcuuid == "" {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not find lcuuid param"))
		return
	}
	orgID, _ := c.Get(HEADER_KEY_X_ORG_ID)
	orgIDInt := orgID.(int)
	db, err := metadb.GetDB(orgIDInt)
	if err != nil {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, err.Error()))
		return
	}
	upgradeInfo := UpgradeInfo{}
	err = c.BindJSON(&upgradeInfo)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("orgID=%d, %s", orgIDInt, err)))
		return
	}

	vtapRrepo, err := dbmgr.DBMgr[models.VTapRepo](db.DB).GetFieldsFromName(
		[]string{"rev_count", "commit_id"}, upgradeInfo.ImageName)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("orgID=%d, %s", orgIDInt, err)))
		return
	}
	var expectedRevision string
	if vtapRrepo.RevCount != "" && vtapRrepo.CommitID != "" {
		expectedRevision = vtapRrepo.RevCount + "-" + vtapRrepo.CommitID
	}
	if len(expectedRevision) == 0 {
		errLog := fmt.Sprintf("orgID=%d get vtapRepo(%s) failed RevCount=%s CommitID=%s",
			orgIDInt, upgradeInfo.ImageName, vtapRrepo.RevCount, vtapRrepo.CommitID)
		log.Error(errLog)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, errLog))
		return
	}

	vtap, err := dbmgr.DBMgr[models.VTap](db.DB).GetFromLcuuid(lcuuid)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("orgID=%d, %s", orgIDInt, err)))
		return
	}
	key := vtap.CtrlIP + "-" + vtap.CtrlMac
	vTapCache := trisolaris.GetORGVTapInfo(orgIDInt).GetVTapCache(key)
	if vTapCache == nil {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("orgID=%d, not found vtap cache", orgIDInt)))
		return
	}
	vTapCache.UpdateUpgradeInfo(expectedRevision, upgradeInfo.ImageName)
	refresh.RefreshCache(orgIDInt, []DataChanged{DATA_CHANGED_VTAP})
	log.Infof("vtap(%s, %s) upgrade:(%s, %s)", vtap.Name, key, expectedRevision, upgradeInfo.ImageName)
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func CancelUpgrade(c *gin.Context) {
	var err error
	lcuuid := c.Param("lcuuid")
	if lcuuid == "" {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, "not find lcuuid param"))
		return
	}
	orgID, _ := c.Get(HEADER_KEY_X_ORG_ID)
	orgIDInt := orgID.(int)
	db, err := metadb.GetDB(orgIDInt)
	if err != nil {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, err.Error()))
		return
	}

	vtap, err := dbmgr.DBMgr[models.VTap](db.DB).GetFromLcuuid(lcuuid)
	if err != nil {
		log.Error(err)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("orgID=%d, %s", orgIDInt, err)))
		return
	}
	key := vtap.CtrlIP + "-" + vtap.CtrlMac
	vTapCache := trisolaris.GetORGVTapInfo(orgIDInt).GetVTapCache(key)
	if vTapCache == nil {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("orgID=%d, not found vtap cache", orgIDInt)))
		return
	}

	// if upgrade is completed, should return error message
	if vTapCache.GetExpectedRevision() == "" || vTapCache.GetExpectedRevision() == vTapCache.GetRevision() {
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, fmt.Sprintf("orgID=%d, vtap(%s, %s) upgrade is completed, unable to cancel", orgIDInt, vtap.Name, key)))
		return
	}

	// cancel upgrade
	vTapCache.UpdateUpgradeInfo("", "")
	refresh.RefreshCache(orgIDInt, []DataChanged{DATA_CHANGED_VTAP})
	log.Infof("vtap(%s, %s) upgrade is canceled", vtap.Name, key)
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*UpgradeService) Register(mux *gin.Engine) {
	mux.PATCH("v1/upgrade/vtap/:lcuuid/", Upgrade)
	mux.PATCH("v1/cancel-upgrade/vtap/:lcuuid/", CancelUpgrade)
}
