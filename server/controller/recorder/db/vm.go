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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
)

type VM struct {
	OperatorBase[*metadbmodel.VM, metadbmodel.VM]
}

func NewVM() *VM {
	operator := &VM{
		newOperatorBase[*metadbmodel.VM](
			ctrlrcommon.RESOURCE_TYPE_VM_EN,
			true,
			true,
		),
	}
	return operator
}

func (v *VM) DeleteBatch(lcuuids []string) ([]*metadbmodel.VM, bool) {
	var vmPodNodeConns []*metadbmodel.VMPodNodeConnection
	err := v.metadata.DB.Model(&metadbmodel.VMPodNodeConnection{}).Joins("JOIN vm On vm_pod_node_connection.vm_id = vm.id").Where("vm.lcuuid IN ?", lcuuids).Scan(&vmPodNodeConns).Error
	if err != nil {
		log.Errorf("get %s (%s lcuuids: %+v) failed: %v", ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, ctrlrcommon.RESOURCE_TYPE_VM_EN, lcuuids, err.Error(), v.metadata.LogPrefixes)
		return nil, false
	} else {
		for _, con := range vmPodNodeConns {
			err = v.metadata.DB.Delete(con).Error
			if err != nil {
				log.Errorf("%s (info: %+v) failed: %v", common.LogDelete(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN), con, err.Error(), v.metadata.LogPrefixes)
				continue
			}
			log.Infof("%s (info: %+v) success", common.LogDelete(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN), con, v.metadata.LogPrefixes)
		}
	}

	var dbItems []*metadbmodel.VM
	err = v.metadata.DB.Where("lcuuid IN ?", lcuuids).Delete(&dbItems).Error
	if err != nil {
		log.Errorf("%s (lcuuids: %v) failed: %v", common.LogDelete(ctrlrcommon.RESOURCE_TYPE_VM_EN), lcuuids, err.Error(), v.metadata.LogPrefixes)
		return nil, false
	}
	log.Infof("%s (lcuuids: %v) success", common.LogDelete(ctrlrcommon.RESOURCE_TYPE_VM_EN), lcuuids, v.metadata.LogPrefixes)
	return dbItems, true
}
