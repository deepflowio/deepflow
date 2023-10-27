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
	"time"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DiffBaseDataSet) addPod(dbItem *mysql.Pod, seq int, toolDataSet *ToolDataSet) {
	podNodeLcuuid, _ := toolDataSet.GetPodNodeLcuuidByID(dbItem.PodNodeID)
	var podReplicaSetLcuuid string
	if dbItem.PodReplicaSetID != 0 {
		podReplicaSetLcuuid, _ = toolDataSet.GetPodReplicaSetLcuuidByID(dbItem.PodReplicaSetID)
	}
	var podGroupLcuuid string
	if dbItem.PodGroupID != 0 {
		podGroupLcuuid, _ = toolDataSet.GetPodGroupLcuuidByID(dbItem.PodGroupID)
	}
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.Pods[dbItem.Lcuuid] = &Pod{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:                dbItem.Name,
		Label:               dbItem.Label,
		Annotation:          dbItem.Annotation,
		ENV:                 dbItem.ENV,
		ContainerIDs:        dbItem.ContainerIDs,
		State:               dbItem.State,
		CreatedAt:           dbItem.CreatedAt,
		PodNodeLcuuid:       podNodeLcuuid,
		PodReplicaSetLcuuid: podReplicaSetLcuuid,
		PodGroupLcuuid:      podGroupLcuuid,
		VPCLcuuid:           vpcLcuuid,
		RegionLcuuid:        dbItem.Region,
		AZLcuuid:            dbItem.AZ,
		SubDomainLcuuid:     dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_EN, b.Pods[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePod(lcuuid string) {
	delete(b.Pods, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_EN, lcuuid))
}

type Pod struct {
	DiffBase
	Name                string    `json:"name"`
	Label               string    `json:"label"`
	Annotation          string    `json:"annotation"`
	ENV                 string    `json:"env"`
	ContainerIDs        string    `json:"container_ids"`
	State               int       `json:"state"`
	CreatedAt           time.Time `json:"created_at"`
	PodNodeLcuuid       string    `json:"pod_node_lcuuid"`
	PodReplicaSetLcuuid string    `json:"pod_replica_set_lcuuid"`
	PodGroupLcuuid      string    `json:"pod_group_lcuuid"`
	VPCLcuuid           string    `json:"vpc_lcuuid"`
	RegionLcuuid        string    `json:"region_lcuuid"`
	AZLcuuid            string    `json:"az_lcuuid"`
	SubDomainLcuuid     string    `json:"sub_domain_lcuuid"`
}

func (p *Pod) Update(cloudItem *cloudmodel.Pod) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.ENV = cloudItem.ENV
	p.Annotation = cloudItem.Annotation
	p.ContainerIDs = cloudItem.ContainerIDs
	p.State = cloudItem.State
	p.CreatedAt = cloudItem.CreatedAt
	p.PodNodeLcuuid = cloudItem.PodNodeLcuuid
	p.PodReplicaSetLcuuid = cloudItem.PodReplicaSetLcuuid
	p.PodGroupLcuuid = cloudItem.PodGroupLcuuid
	p.VPCLcuuid = cloudItem.VPCLcuuid
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_EN, p))
}
