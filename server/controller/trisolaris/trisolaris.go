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

package trisolaris

import (
	"time"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/election"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/kubernetes"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/node"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/vtap"
)

var log = logging.MustGetLogger("trisolaris")

type Trisolaris struct {
	config         *config.Config
	dbConn         *gorm.DB
	metaData       *metadata.MetaData
	vTapInfo       *vtap.VTapInfo
	nodeInfo       *node.NodeInfo
	kubernetesInfo *kubernetes.KubernetesInfo
	refreshOP      *refresh.RefreshOP
}

var trisolaris *Trisolaris

func GetMetaData() *metadata.MetaData {
	return trisolaris.metaData
}

func GetGVTapInfo() *vtap.VTapInfo {
	return trisolaris.vTapInfo
}

func GetGNodeInfo() *node.NodeInfo {
	return trisolaris.nodeInfo
}

func GetGKubernetesInfo() *kubernetes.KubernetesInfo {
	return trisolaris.kubernetesInfo
}

func GetConfig() *config.Config {
	return trisolaris.config
}

func GetDB() *gorm.DB {
	return trisolaris.dbConn
}

func GetBillingMethod() string {
	return trisolaris.config.BillingMethod
}

func GetGrpcPort() int {
	return trisolaris.config.GetGrpcPort()
}

func GetIngesterPort() int {
	return trisolaris.config.GetIngesterPort()
}

func PutPlatformData() {
	trisolaris.metaData.PutChPlatformData()
}

func PutTapType() {
	trisolaris.metaData.PutChTapType()
}

func PutNodeInfo() {
	trisolaris.nodeInfo.PutChNodeInfo()
}

func PutVTapCache() {
	trisolaris.vTapInfo.PutVTapCacheRefresh()
}

func PutFlowACL() {
	trisolaris.metaData.PutChPolicy()
}

func PutGroup() {
	trisolaris.metaData.PutChGroup()
}

func (t *Trisolaris) getStartTime() int64 {
	startTime := int64(0)
	for {
		startTime = election.GetAcquireTime()
		if startTime == 0 {
			log.Errorf("get start time(%d) failed", startTime)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}

	log.Infof("get start time(%d) success", startTime)

	return startTime
}

func (t *Trisolaris) Start() {
	t.metaData.InitData(t.getStartTime()) // 需要先初始化
	go t.metaData.TimedRefreshMetaData()
	go t.kubernetesInfo.TimedRefreshClusterID()
	go t.vTapInfo.TimedRefreshVTapCache()
	go t.nodeInfo.TimedRefreshNodeCache()
	go t.refreshOP.TimedRefreshIPs()
}

func NewTrisolaris(cfg *config.Config, db *gorm.DB) *Trisolaris {
	if trisolaris == nil {
		cfg.Convert()
		metaData := metadata.NewMetaData(db, cfg)
		nodeInfo := node.NewNodeInfo(db, metaData, cfg)
		trisolaris = &Trisolaris{
			config:         cfg,
			dbConn:         db,
			metaData:       metaData,
			vTapInfo:       vtap.NewVTapInfo(db, metaData, cfg),
			nodeInfo:       nodeInfo,
			kubernetesInfo: kubernetes.NewKubernetesInfo(db, cfg),
			refreshOP:      refresh.NewRefreshOP(db, cfg.NodeIP),
		}
	} else {
		return trisolaris
	}

	return trisolaris
}
