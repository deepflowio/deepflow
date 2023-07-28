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

package mysql

import (
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type PodGroup struct {
	DataProvider
	dataTool *PodGroupToolData
}

func NewPodGroup() *PodGroup {
	dp := &PodGroup{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_GROUP_EN), new(PodGroupToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *PodGroup) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.PodGroups {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *PodGroup) generateOne(item mysql.PodGroup) common.ResponseElem {
	d := MySQLModelToMap(item)

	d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
	epcID := p.dataTool.podClusterIDToEPCID[item.PodClusterID]
	d["EPC_ID"] = epcID
	d["EPC_NAME"] = p.dataTool.vpcIDToName[epcID]
	d["POD_CLUSTER_NAME"] = p.dataTool.podClusterIDToName[item.PodClusterID]
	d["POD_NAMESPACE_NAME"] = p.dataTool.podNamespaceIDToName[item.PodNamespaceID]
	d["RUNNING_POD_COUNT"] = len(p.dataTool.podGroupIDToRunningPodIDs[item.ID])
	d["POD_REPLICA_SET_COUNT"] = len(p.dataTool.podGroupIDToPodReplicaSetIDs[item.ID])

	return d
}

type PodGroupToolData struct {
	PodGroups []mysql.PodGroup

	azLcuuidToName               map[string]string
	vpcIDToName                  map[int]string
	podClusterIDToName           map[int]string
	podClusterIDToEPCID          map[int]int
	podNamespaceIDToName         map[int]string
	podGroupIDToRunningPodIDs    map[int][]int
	podGroupIDToPodReplicaSetIDs map[int][]int
}

func (td *PodGroupToolData) Init() *PodGroupToolData {
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.podClusterIDToName = make(map[int]string)
	td.podClusterIDToEPCID = make(map[int]int)
	td.podNamespaceIDToName = make(map[int]string)
	td.podGroupIDToRunningPodIDs = make(map[int][]int)
	td.podGroupIDToPodReplicaSetIDs = make(map[int][]int)

	return td
}

func (td *PodGroupToolData) Load() (err error) {
	err = mysql.Db.Unscoped().Find(&td.PodGroups).Error // TODO use db mng

	var azs []mysql.AZ
	err = mysql.Db.Unscoped().Select("lcuuid", "name").Find(&azs).Error
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}
	var vpcs []mysql.VPC
	err = mysql.Db.Unscoped().Select("id", "name").Find(&vpcs).Error
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}
	var podClusters []mysql.PodCluster
	err = mysql.Db.Unscoped().Select("id", "name", "epc_id").Find(&podClusters).Error
	for _, item := range podClusters {
		td.podClusterIDToName[item.ID] = item.Name
		td.podClusterIDToEPCID[item.ID] = item.VPCID
	}
	var podNamespaces []mysql.PodNamespace
	err = mysql.Db.Unscoped().Select("id", "name").Find(&podNamespaces).Error
	for _, item := range podNamespaces {
		td.podNamespaceIDToName[item.ID] = item.Name
	}
	var pods []mysql.Pod
	err = mysql.Db.Unscoped().Select("id", "pod_group_id", "state").Find(&pods).Error
	for _, pod := range pods {
		if pod.State == ctrlcommon.POD_STATE_RUNNING {
			td.podGroupIDToRunningPodIDs[pod.PodGroupID] = append(td.podGroupIDToRunningPodIDs[pod.PodGroupID], pod.ID)
		}
	}
	var podReplicaSets []mysql.PodReplicaSet
	err = mysql.Db.Unscoped().Select("id", "pod_group_id").Find(&podReplicaSets).Error
	for _, podReplicaSet := range podReplicaSets {
		td.podGroupIDToPodReplicaSetIDs[podReplicaSet.PodGroupID] = append(
			td.podGroupIDToPodReplicaSetIDs[podReplicaSet.PodGroupID],
			podReplicaSet.ID,
		)
	}

	return
}
