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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func (b *DataSet) AddPodService(dbItem *metadbmodel.PodService, seq int, toolDataSet *tool.DataSet) {
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
		Metadata:         dbItem.Metadata,
		MetadataHash:     dbItem.MetadataHash,
		Spec:             dbItem.Spec,
		SpecHash:         dbItem.SpecHash,
		PodIngressLcuuid: podIngressLcuuid,
		RegionLcuuid:     dbItem.Region,
		AZLcuuid:         dbItem.AZ,
		SubDomainLcuuid:  dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, b.PodServices[dbItem.Lcuuid]), b.metadata.LogPrefixes)
}

func (b *DataSet) DeletePodService(lcuuid string) {
	delete(b.PodServices, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, lcuuid), b.metadata.LogPrefixes)
}

type PodService struct {
	DiffBase
	Name             string `json:"name"`
	Label            string `json:"label"`
	Annotation       string `json:"annotation"`
	Selector         string `json:"selector"`
	ExternalIP       string `json:"external_ip"`
	ServiceClusterIP string `json:"service_cluster_ip"`
	Metadata         string `json:"metadata"`
	MetadataHash     string `json:"metadata_hash"`
	Spec             string `json:"spec"`
	SpecHash         string `json:"spec_hash"`
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
	p.Metadata = cloudItem.Metadata
	p.MetadataHash = cloudItem.MetadataHash
	p.Spec = cloudItem.Spec
	p.SpecHash = cloudItem.SpecHash
	p.PodIngressLcuuid = cloudItem.PodIngressLcuuid
	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, p))
}
