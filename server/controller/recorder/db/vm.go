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

package db

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type VM struct {
	OperatorBase[mysql.VM]
}

func NewVM() *VM {
	operater := &VM{
		OperatorBase[mysql.VM]{
			resourceTypeName: ctrlrcommon.RESOURCE_TYPE_VM_EN,
			softDelete:       true,
			allocateID:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *VM) setDBItemID(dbItem *mysql.VM, id int) {
	dbItem.ID = id
}

func (v *VM) DeleteBatch(lcuuids []string) ([]*mysql.VM, bool) {
	var vmPodNodeConns []*mysql.VMPodNodeConnection
	err := v.metadata.DB.Model(&mysql.VMPodNodeConnection{}).Joins("JOIN vm On vm_pod_node_connection.vm_id = vm.id").Where("vm.lcuuid IN ?", lcuuids).Scan(&vmPodNodeConns).Error
	if err != nil {
		log.Error(v.metadata.LogPre("get %s (%s lcuuids: %+v) failed: %v", ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, lcuuids, err))
		return nil, false
	} else {
		for _, con := range vmPodNodeConns {
			err = v.metadata.DB.Delete(con).Error
			if err != nil {
				log.Error(v.metadata.LogPre("delete %s (info: %+v) failed: %v", ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, con, err))
				continue
			}
			log.Info(v.metadata.LogPre("delete %s (info: %+v) success", ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, con))
		}
	}

	var dbItems []*mysql.VM
	err = v.metadata.DB.Where("lcuuid IN ?", lcuuids).Delete(&dbItems).Error
	if err != nil {
		log.Error(v.metadata.LogPre("delete %s (lcuuids: %v) failed: %v", ctrlrcommon.RESOURCE_TYPE_VM_EN, lcuuids, err))
		return nil, false
	}
	log.Info(v.metadata.LogPre("delete %s (lcuuids: %v) success", ctrlrcommon.RESOURCE_TYPE_VM_EN, lcuuids))
	return dbItems, true
}
