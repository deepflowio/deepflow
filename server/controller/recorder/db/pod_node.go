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

type PodNode struct {
	OperatorBase[mysql.PodNode]
}

func NewPodNode() *PodNode {
	operater := &PodNode{
		OperatorBase[mysql.PodNode]{
			resourceTypeName: ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN,
			softDelete:       true,
			allocateID:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *PodNode) setDBItemID(dbItem *mysql.PodNode, id int) {
	dbItem.ID = id
}

func (n *PodNode) DeleteBatch(lcuuids []string) ([]*mysql.PodNode, bool) {
	var vmPodNodeConns []*mysql.VMPodNodeConnection
	err := n.metadata.DB.Model(&mysql.VMPodNodeConnection{}).Joins("JOIN pod_node On vm_pod_node_connection.pod_node_id = pod_node.id").Where("pod_node.lcuuid IN ?", lcuuids).Scan(&vmPodNodeConns).Error
	if err != nil {
		log.Error(n.metadata.LogPre("get %s (%s lcuuids: %+v) failed: %v", ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, lcuuids, err))
		return nil, false
	} else {
		for _, con := range vmPodNodeConns {
			err = n.metadata.DB.Delete(con).Error
			if err != nil {
				log.Error(n.metadata.LogPre("delete %s (info: %+v) failed: %v", ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, con, err))
				continue
			}
			log.Info(n.metadata.LogPre("delete %s (info: %+v) success", ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, con))
		}
	}

	var dbItems []*mysql.PodNode
	err = n.metadata.DB.Where("lcuuid IN ?", lcuuids).Delete(&dbItems).Error
	if err != nil {
		log.Error(n.metadata.LogPre("delete %s (lcuuids: %v) failed: %v", ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, lcuuids, err))
		return nil, false
	}
	log.Info(n.metadata.LogPre("delete %s (lcuuids: %v) success", ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, lcuuids))
	return dbItems, true
}
