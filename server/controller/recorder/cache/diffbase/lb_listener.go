/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DataSet) AddLBListener(dbItem *mysql.LBListener, seq int) {
	b.LBListeners[dbItem.Lcuuid] = &LBListener{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:     dbItem.Name,
		IPs:      dbItem.IPs,
		SNATIPs:  dbItem.SNATIPs,
		Port:     dbItem.Port,
		Protocol: dbItem.Protocol,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, b.LBListeners[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteLBListener(lcuuid string) {
	delete(b.LBListeners, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, lcuuid))
}

type LBListener struct {
	DiffBase
	Name     string `json:"name"`
	IPs      string `json:"ips"`
	SNATIPs  string `json:"snat_ips"`
	Port     int    `json:"port"`
	Protocol string `json:"protocal"`
}

func (l *LBListener) Update(cloudItem *cloudmodel.LBListener) {
	l.Name = cloudItem.Name
	l.IPs = cloudItem.IPs
	l.SNATIPs = cloudItem.SNATIPs
	l.Port = cloudItem.Port
	l.Protocol = cloudItem.Protocol
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_LB_LISTENER_EN, l))
}
