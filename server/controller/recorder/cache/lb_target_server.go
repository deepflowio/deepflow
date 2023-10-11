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

package cache

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DiffBaseDataSet) addLBTargetServer(dbItem *mysql.LBTargetServer, seq int) {
	b.LBTargetServers[dbItem.Lcuuid] = &LBTargetServer{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		IP:       dbItem.IP,
		Port:     dbItem.Port,
		Protocol: dbItem.Protocol,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, b.LBTargetServers[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteLBTargetServer(lcuuid string) {
	delete(b.LBTargetServers, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, lcuuid))
}

type LBTargetServer struct {
	DiffBase
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocal"`
}

func (l *LBTargetServer) Update(cloudItem *cloudmodel.LBTargetServer) {
	l.IP = cloudItem.IP
	l.Port = cloudItem.Port
	l.Protocol = cloudItem.Protocol
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_TARGET_SERVER_EN, l))
}
