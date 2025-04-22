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

package service

import (
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
)

func GrafanaProfile(args model.Profile, cfg *config.QuerierConfig, where string) (result *model.GrafanaProfileValue, debug interface{}, err error) {
	result = &model.GrafanaProfileValue{}
	result.Columns = []string{"level", "function", "self_value", "total_value"}

	tree, generateDebug, err := GenerateProfile(args, cfg, where, model.ProfileDebug{})
	debug = generateDebug
	if err != nil {
		return
	}
	nodes := tree.NodeValues.Values
	if len(nodes) == 0 {
		return
	}

	// append node_child_ids
	newNodes := [][5]interface{}{}
	for _, node := range nodes {
		// columns: ["function_id", "parent_node_id", "self_value", "total_value", "node_child_ids"]
		newNode := [5]interface{}{}
		newNode[0] = node[0]
		newNode[1] = node[1]
		newNode[2] = node[2]
		newNode[3] = node[3]
		newNode[4] = &[]int{}
		newNodes = append(newNodes, newNode)
	}

	// update node_child_ids
	for i, newNode := range newNodes {
		if newNode[1] != -1 {
			childIDs := newNodes[newNode[1].(int)][4].(*[]int)
			*childIDs = append(*childIDs, i)
		}
	}
	convertNode(newNodes[0], 0, result, tree.Functions, newNodes)
	return
}

/*
convert to the data format
such as:

	{
		"fields": [
			{"name": "level", "values": [0, 1, 2, 2, 2, 1]},
			{"name": "value", "values": [100, 60, 30, 20, 10, 40]},
			{"name": "label", "values": ["root", "function1", "subfunction1", "subfunction2", "subfunction3", "function2"]},
			{"name": "self", "values": [0, 10, 30, 20, 10, 40]}
		]
	}

https://play.grafana.org/d/cdl34qv4zzg8wa/flame-graphs?orgId=1
*/
func convertNode(node [5]interface{}, level int, result *model.GrafanaProfileValue, functions []string, newNodes [][5]interface{}) {
	result.Values = append(result.Values, []interface{}{level, functions[node[0].(int)], node[2].(int), node[3].(int)})
	childIDs := node[4].(*[]int)
	for _, childID := range *childIDs {
		convertNode(newNodes[childID], level+1, result, functions, newNodes)
	}
}
