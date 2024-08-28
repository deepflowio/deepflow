/*
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

package tagrecorder

import (
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

type ChNodeType struct {
	UpdaterBase[mysqlmodel.ChNodeType, NodeTypeKey]
}

func NewChNodeType() *ChNodeType {
	updater := &ChNodeType{
		UpdaterBase[mysqlmodel.ChNodeType, NodeTypeKey]{
			resourceTypeName: RESOURCE_TYPE_CH_NODE_TYPE,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (n *ChNodeType) generateNewData() (map[NodeTypeKey]mysqlmodel.ChNodeType, bool) {
	keyToItem := make(map[NodeTypeKey]mysqlmodel.ChNodeType)
	for resourceType, nodeType := range RESOURCE_TYPE_TO_NODE_TYPE {
		keyToItem[NodeTypeKey{ResourceType: resourceType}] = mysqlmodel.ChNodeType{
			ResourceType: resourceType,
			NodeType:     nodeType,
		}
	}
	return keyToItem, true
}

func (n *ChNodeType) generateKey(dbItem mysqlmodel.ChNodeType) NodeTypeKey {
	return NodeTypeKey{ResourceType: dbItem.ResourceType}
}

func (n *ChNodeType) generateUpdateInfo(oldItem, newItem mysqlmodel.ChNodeType) (map[string]interface{}, bool) {
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
