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

package db

import (
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
)

type PodNode struct {
	OperatorBase[mysql.PodNode]
}

func NewPodNode() *PodNode {
	operater := &PodNode{
		OperatorBase[mysql.PodNode]{
			resourceTypeName: common.RESOURCE_TYPE_POD_NODE_EN,
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

func (n *PodNode) DeleteBatch(lcuuids []string) bool {
	var vmPodNodeConns []*mysql.VMPodNodeConnection
	err := mysql.Db.Model(&mysql.VMPodNodeConnection{}).Joins("JOIN pod_node On vm_pod_node_connection.pod_node_id = pod_node.id").Where("pod_node.lcuuid IN ?", lcuuids).Scan(&vmPodNodeConns).Error
	if err != nil {
		log.Errorf("get %s (%s lcuuids: %+v) failed: %v", common.RESOURCE_TYPE_POD_NODE_EN, common.RESOURCE_TYPE_POD_NODE_EN, lcuuids, err)
		return false
	} else {
		for _, con := range vmPodNodeConns {
			err = mysql.Db.Delete(con).Error
			if err != nil {
				log.Errorf("delete %s (info: %+v) failed: %v", common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, con, err)
				continue
			}
			log.Infof("delete %s (info: %+v) success", common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN, con)
		}
	}
	err = mysql.Db.Where("lcuuid IN ?", lcuuids).Delete(&mysql.PodNode{}).Error
	if err != nil {
		log.Errorf("delete %s (lcuuids: %v) failed: %v", common.RESOURCE_TYPE_POD_NODE_EN, lcuuids, err)
		return false
	}
	log.Infof("delete %s (lcuuids: %v) success", common.RESOURCE_TYPE_POD_NODE_EN, lcuuids)
	return true
}
