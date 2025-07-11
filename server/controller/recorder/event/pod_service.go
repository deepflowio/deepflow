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

package event

import (
	"sigs.k8s.io/yaml"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodService struct {
	EventManagerBase
	deviceType int
}

func NewPodService(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *PodService {
	mng := &PodService{
		newEventManagerBase(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN,
			toolDS,
			eq,
		),
		ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE,
	}
	return mng
}

func (p *PodService) ProduceByAdd(items []*mysqlmodel.PodService) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		info, err := p.ToolDataSet.GetPodServiceInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagPodServiceID(item.ID), // TODO 此字段在 ingester 中并未被使用，待删除
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagL3DeviceType(p.deviceType),
			eventapi.TagL3DeviceID(item.ID),
			eventapi.TagPodClusterID(item.PodClusterID),
			eventapi.TagPodNSID(item.PodNamespaceID),
		}...)

		p.createInstanceAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (p *PodService) ProduceByUpdate(cloudItem *cloudmodel.PodService, diffBase *diffbase.PodService) {
	if cloudItem.MetadataHash == diffBase.MetadataHash && cloudItem.SpecHash == diffBase.SpecHash {
		// no changes
		return
	}

	newMetadata, err := yaml.JSONToYAML([]byte(cloudItem.Metadata))
	if err != nil {
		log.Errorf("failed to convert JSON metadata: %v to YAML: %s", cloudItem.Metadata, p.metadata.LogPrefixes)
		return
	}
	newSpec, err := yaml.JSONToYAML([]byte(cloudItem.Spec))
	if err != nil {
		log.Errorf("failed to convert JSON spec: %v to YAML: %s", cloudItem.Spec, p.metadata.LogPrefixes)
		return
	}

	id, ok := p.ToolDataSet.GetPodServiceIDByLcuuid(diffBase.Lcuuid)
	if !ok {
		log.Errorf("pod service id not found for lcuuid: %s", diffBase.Lcuuid, p.metadata.LogPrefixes)
		return
	}

	var opts []eventapi.TagFieldOption
	old := JoinMetadataAndSpec(diffBase.Metadata, diffBase.Spec)
	new := JoinMetadataAndSpec(string(newMetadata), string(newSpec))
	if old == "" || new == "" {
		return
	} else {
		diff := CompareConfig(old, new, int(p.metadata.Config.EventCfg.ConfigDiffContext))

		opts = []eventapi.TagFieldOption{
			eventapi.TagPodServiceID(id), // TODO 此字段在 ingester 中并未被使用，待删除
			eventapi.TagL3DeviceType(p.deviceType),
			eventapi.TagL3DeviceID(id),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfig, eventapi.AttributeNameConfigDiff},
				[]string{new, diff}),
		}
	}
	p.createInstanceAndEnqueue(diffBase.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_MODIFY, diffBase.Name, p.deviceType, id, opts...)
}

func (p *PodService) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := p.ToolDataSet.GetPodServiceIDByLcuuid(lcuuid)
		if ok {
			var err error
			name, err = p.ToolDataSet.GetPodServiceNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(p.resourceType, lcuuid), err, p.metadata.LogPrefixes)
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		p.createInstanceAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, p.deviceType, id)
	}
}
