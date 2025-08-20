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

type PodGroup struct {
	EventManagerBase
}

func NewPodGroup(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *PodGroup {
	mng := &PodGroup{
		newEventManagerBase(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN,
			toolDS,
			eq,
		),
	}
	return mng
}

func (p *PodGroup) ProduceByAdd(items []*mysqlmodel.PodGroup) {
}

func (p *PodGroup) ProduceByUpdate(cloudItem *cloudmodel.PodGroup, diffBase *diffbase.PodGroup) {
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

	var opts []eventapi.TagFieldOption
	old := JoinMetadataAndSpec(diffBase.Metadata, diffBase.Spec)
	new := JoinMetadataAndSpec(string(newMetadata), string(newSpec))
	if old == "" || new == "" {
		return
	} else {
		diff := CompareConfig(old, new, int(p.metadata.Config.EventCfg.ConfigDiffContext))

		id, ok := p.ToolDataSet.GetPodGroupIDByLcuuid(diffBase.Lcuuid)
		if !ok {
			log.Errorf("pod service id not found for lcuuid: %s", diffBase.Lcuuid, p.metadata.LogPrefixes)
			return
		}
		podGroupType, ok := p.ToolDataSet.GetPodGroupTypeByID(id)
		if !ok {
			log.Errorf("pod service type not found for id: %d", id, p.metadata.LogPrefixes)
		}
		opts = []eventapi.TagFieldOption{
			eventapi.TagPodGroupID(id),
			// We need to provide pod group type information for ingester to recognize auto_service classification
			eventapi.TagPodGroupType(uint32(podGroupType)),
			// Provide instance type to fill in auto_instance information
			// Pod group itself does not have an instance type, but its changes essentially affect pods,
			// so the type is set to pod; since it affects many pods, the auto instance id remains 0
			eventapi.TagInstanceType(uint32(ctrlrcommon.VIF_DEVICE_TYPE_POD)),
			eventapi.TagAttributes(
				[]string{eventapi.AttributeNameConfig, eventapi.AttributeNameConfigDiff},
				[]string{new, diff}),
		}
	}
	p.createAndEnqueue(diffBase.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_MODIFY, opts...)
}

func (p *PodGroup) ProduceByDelete(lcuuids []string) {
}
