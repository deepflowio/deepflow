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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/recorder/common"
)

func (b *DiffBaseDataSet) addPodService(dbItem *mysql.PodService, seq int, toolDataSet *ToolDataSet) {
	var podIngressLcuuid string
	if dbItem.PodIngressID != 0 {
		podIngressLcuuid, _ = toolDataSet.GetPodIngressLcuuidByID(dbItem.PodIngressID)
	}
	b.PodServices[dbItem.Lcuuid] = &PodService{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:             dbItem.Name,
		Label:            dbItem.Label,
		Annotation:       dbItem.Annotation,
		Selector:         dbItem.Selector,
		ServiceClusterIP: dbItem.ServiceClusterIP,
		PodIngressLcuuid: podIngressLcuuid,
		RegionLcuuid:     dbItem.Region,
		AZLcuuid:         dbItem.AZ,
		SubDomainLcuuid:  dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(RESOURCE_TYPE_POD_SERVICE_EN, b.PodServices[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deletePodService(lcuuid string) {
	delete(b.PodServices, lcuuid)
	log.Info(deleteDiffBase(RESOURCE_TYPE_POD_SERVICE_EN, lcuuid))
}

type PodService struct {
	DiffBase
	Name             string `json:"name"`
	Label            string `json:"label"`
	Annotation       string `json:"annotation"`
	Selector         string `json:"selector"`
	ServiceClusterIP string `json:"service_cluster_ip"`
	PodIngressLcuuid string `json:"pod_ingress_lcuuid"`
	RegionLcuuid     string `json:"region_lcuuid"`
	AZLcuuid         string `json:"az_lcuuid"`
	SubDomainLcuuid  string `json:"sub_domain_lcuuid"`
}

func (p *PodService) Update(cloudItem *cloudmodel.PodService) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.Annotation = cloudItem.Annotation
	p.Selector = cloudItem.Selector
	p.ServiceClusterIP = cloudItem.ServiceClusterIP
	p.PodIngressLcuuid = cloudItem.PodIngressLcuuid
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(RESOURCE_TYPE_POD_SERVICE_EN, p))
}
