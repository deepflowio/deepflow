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

package tagrecorder

import (
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChNodeType struct {
	UpdaterComponent[metadbmodel.ChNodeType, NodeTypeKey]
}

func NewChNodeType() *ChNodeType {
	updater := &ChNodeType{
		newUpdaterComponent[metadbmodel.ChNodeType, NodeTypeKey](
			RESOURCE_TYPE_CH_NODE_TYPE,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (n *ChNodeType) generateNewData(db *metadb.DB) (map[NodeTypeKey]metadbmodel.ChNodeType, bool) {
	keyToItem := make(map[NodeTypeKey]metadbmodel.ChNodeType)
	for resourceType, nodeType := range RESOURCE_TYPE_TO_NODE_TYPE {
		keyToItem[NodeTypeKey{ResourceType: resourceType}] = metadbmodel.ChNodeType{
			ResourceType: &resourceType,
			NodeType:     nodeType,
		}
	}
	return keyToItem, true
}

func (n *ChNodeType) generateKey(dbItem metadbmodel.ChNodeType) NodeTypeKey {
	return NodeTypeKey{ResourceType: *dbItem.ResourceType}
}

func (n *ChNodeType) generateUpdateInfo(oldItem, newItem metadbmodel.ChNodeType) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.NodeType != newItem.NodeType {
		updateInfo["node_type"] = newItem.NodeType
		updateInfo["resource_type"] = newItem.ResourceType
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
