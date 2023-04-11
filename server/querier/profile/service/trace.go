/*
 * Copyright (c) 2022 Yunshan Networks
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
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/exp/slices"

	logging "github.com/op/go-logging"

	controller_common "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/profile/common"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
)

var log = logging.MustGetLogger("profile")

func Tracing(args model.ProfileTracing, cfg *config.QuerierConfig) (result []*model.ProfileTreeNode, err error) {
	whereSlice := []string{}
	whereSlice = append(whereSlice, fmt.Sprintf(" time>=%d", args.TimeStart))
	whereSlice = append(whereSlice, fmt.Sprintf(" time<=%d", args.TimeEnd))
	whereSlice = append(whereSlice, fmt.Sprintf(" app_service='%s'", args.AppService))
	whereSlice = append(whereSlice, fmt.Sprintf(" profile_language_type='%s'", args.ProfileLanguageType))
	whereSlice = append(whereSlice, fmt.Sprintf(" profile_event_type='%s'", args.ProfileEventType))
	if args.TagFilter != "" {
		whereSlice = append(whereSlice, " "+args.TagFilter)
	}
	whereSql := strings.Join(whereSlice, " AND")
	limitSql := cfg.Profile.FlameQueryLimit
	url := fmt.Sprintf("http://%s/v1/query/", net.JoinHostPort("localhost", fmt.Sprintf("%d", cfg.ListenPort)))
	body := map[string]interface{}{}
	body["db"] = common.DATABASE_PROFILE
	body["sql"] = fmt.Sprintf(
		"SELECT %s, %s, %s, %s FROM %s WHERE %s LIMIT %d",
		common.PROFILE_LOCATION_STR, common.PROFILE_NODE_ID, common.PROFILE_PARENT_NODE_ID, common.PROFILE_VALUE, common.TABLE_PROFILE, whereSql, limitSql,
	)
	resp, err := controller_common.CURLPerform("POST", url, body)
	if err != nil {
		log.Errorf("call querier failed: %s, %s", err.Error(), url)
		return
	}
	if len(resp.Get("result").MustMap()) == 0 {
		log.Warningf("no data in curl response: %s", url)
		return
	}
	profileLocationStrIndex := -1
	profileNodeIDIndex := -1
	profileParentNodeIDIndex := -1
	profileValueIndex := -1
	NodeIDToProfileTree := map[string]*model.ProfileTreeNode{}
	profileNodeIDToNodeID := map[int]string{}
	columns := resp.GetPath("result", "columns")
	values := resp.GetPath("result", "values")
	for columnIndex := range columns.MustArray() {
		column := columns.GetIndex(columnIndex).MustString()
		switch column {
		case "profile_location_str":
			profileLocationStrIndex = columnIndex
		case "profile_node_id":
			profileNodeIDIndex = columnIndex
		case "profile_parent_node_id":
			profileParentNodeIDIndex = columnIndex
		case "profile_value":
			profileValueIndex = columnIndex
		}
	}
	indexOK := slices.Contains[int]([]int{profileLocationStrIndex, profileNodeIDIndex, profileParentNodeIDIndex, profileValueIndex}, -1)
	if indexOK {
		log.Error("Not all fields found")
		err = errors.New("Not all fields found")
		return
	}
	// merge profile_node_ids, profile_parent_node_ids, self_value
	for valueIndex := range values.MustArray() {
		profileLocationStr := values.GetIndex(valueIndex).GetIndex(profileLocationStrIndex).MustString()
		nodeID := controller_common.GenerateUUID(profileLocationStr)
		profileNodeID := values.GetIndex(valueIndex).GetIndex(profileNodeIDIndex).MustInt()
		profileParentNodeID := values.GetIndex(valueIndex).GetIndex(profileParentNodeIDIndex).MustInt()
		profileValue := values.GetIndex(valueIndex).GetIndex(profileValueIndex).MustInt()
		existNode, ok := NodeIDToProfileTree[nodeID]
		if ok {
			ok = slices.Contains[int](existNode.ProfileNodeIDS, profileNodeID)
			if !ok {
				existNode.ProfileNodeIDS = append(existNode.ProfileNodeIDS, profileNodeID)
			}
			ok = slices.Contains[int](existNode.ProfileParentNodeIDS, profileParentNodeID)
			if !ok && profileParentNodeID != 0 {
				existNode.ProfileParentNodeIDS = append(existNode.ProfileParentNodeIDS, profileParentNodeID)
			}
			existNode.SelfValue += profileValue
			existNode.TotalValue = existNode.SelfValue
		} else {
			node := NewProfileTreeNode(profileLocationStr, nodeID, profileNodeID, profileValue)
			if profileParentNodeID == 0 {
				node.ProfileParentNodeIDS = []int{}
			} else {
				node.ProfileParentNodeIDS = []int{profileParentNodeID}
			}
			NodeIDToProfileTree[nodeID] = node
			profileNodeIDToNodeID[profileNodeID] = nodeID
			result = append(result, node)
		}
	}
	// update parent_node_ids
	for _, node := range NodeIDToProfileTree {
		for _, profileParentNodeID := range node.ProfileParentNodeIDS {
			parentNodeID, ok := profileNodeIDToNodeID[profileParentNodeID]
			if ok {
				node.ParentNodeIDS = append(node.ParentNodeIDS, parentNodeID)
			}
		}
	}
	// update total_value
	for _, node := range NodeIDToProfileTree {
		nodeIDs := []string{node.NodeID}
		parentNode := &model.ProfileTreeNode{}
		UpdateNodeTotalValue(nodeIDs, node, parentNode, NodeIDToProfileTree)
	}
	// format root node
	for _, node := range NodeIDToProfileTree {
		if len(node.ParentNodeIDS) == 0 {
			node.ParentNodeIDS = append(node.ParentNodeIDS, "")
		}
		// remove debug information
		if !args.Debug {
			node.ProfileNodeIDS = node.ProfileNodeIDS[:0]
			node.ProfileParentNodeIDS = node.ProfileParentNodeIDS[:0]
		}
	}
	return
}

func NewProfileTreeNode(profileLocationStr string, nodeID string, profileNodeID int, profileValue int) *model.ProfileTreeNode {
	node := &model.ProfileTreeNode{}
	node.ProfileLocationStr = profileLocationStr
	node.NodeID = nodeID
	node.ProfileNodeIDS = []int{profileNodeID}
	node.SelfValue = profileValue
	node.TotalValue = profileValue
	return node
}

func UpdateNodeTotalValue(nodeIDs []string, node *model.ProfileTreeNode, parentNode *model.ProfileTreeNode, NodeIDToProfileTree map[string]*model.ProfileTreeNode) {
	if parentNode.ProfileLocationStr != "" {
		ok := slices.Contains[string](nodeIDs, parentNode.NodeID)
		if len(node.ParentNodeIDS) == 0 || ok {
			return
		}
		parentNode.TotalValue += node.SelfValue
		nodeIDs = append(nodeIDs, parentNode.NodeID)
	} else {
		parentNode = node
	}
	for _, parentNodeID := range parentNode.ParentNodeIDS {
		parentNode, ok := NodeIDToProfileTree[parentNodeID]
		if ok {
			UpdateNodeTotalValue(nodeIDs, node, parentNode, NodeIDToProfileTree)
		}
	}
}
