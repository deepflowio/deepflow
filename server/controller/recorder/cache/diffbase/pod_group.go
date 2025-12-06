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
	"sigs.k8s.io/yaml"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func (b *DataSet) AddPodGroup(dbItem *metadbmodel.PodGroup, seq int) {
	b.PodGroups[dbItem.Lcuuid] = &PodGroup{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		NetworkMode:     dbItem.NetworkMode,
		PodNum:          dbItem.PodNum,
		Type:            dbItem.Type,
		Metadata:        string(dbItem.Metadata),
		MetadataHash:    dbItem.MetadataHash,
		Spec:            string(dbItem.Spec),
		SpecHash:        dbItem.SpecHash,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, b.PodGroups[dbItem.Lcuuid].ToLoggable()), b.metadata.LogPrefixes)
}

func (b *DataSet) DeletePodGroup(lcuuid string) {
	delete(b.PodGroups, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, lcuuid), b.metadata.LogPrefixes)
}

type PodGroup struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	PodNum          int    `json:"pod_num"`
	Type            int    `json:"type"`
	NetworkMode     int    `json:"network_mode"`
	Metadata        string `json:"metadata"`
	MetadataHash    string `json:"metadata_hash"`
	Spec            string `json:"spec"`
	SpecHash        string `json:"spec_hash"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

// ToLoggable converts PodGroup to a loggable format, excluding fields Spec and Metadata
func (p PodGroup) ToLoggable() interface{} {
	copied := p
	copied.Metadata = "**HIDDEN**"
	copied.Spec = "**HIDDEN**"
	return copied
}

func (p *PodGroup) Update(cloudItem *cloudmodel.PodGroup, toolDataSet *tool.DataSet) {
	p.Name = cloudItem.Name
	p.Label = cloudItem.Label
	p.NetworkMode = cloudItem.NetworkMode
	p.PodNum = cloudItem.PodNum
	p.Type = cloudItem.Type

	yamlMetadata, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
	if err != nil {
		log.Errorf("failed to convert JSON metadata: %v to YAML: %s", cloudItem.Metadata, toolDataSet.GetMetadata().LogPrefixes)
		return
	}
	p.Metadata = string(yamlMetadata)
	p.MetadataHash = cloudItem.MetadataHash

	yamlSpec, err := yaml.JSONToYAML([]byte(cloudItem.Spec))
	if err != nil {
		log.Errorf("failed to convert JSON spec: %v to YAML: %s", cloudItem.Spec, toolDataSet.GetMetadata().LogPrefixes)
		return
	}
	p.Spec = string(yamlSpec)
	p.SpecHash = cloudItem.SpecHash

	p.RegionLcuuid = cloudItem.RegionLcuuid
	p.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, p.ToLoggable()))
}
