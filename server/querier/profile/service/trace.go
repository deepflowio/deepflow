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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	logging "github.com/op/go-logging"

	controller_common "github.com/deepflowio/deepflow/server/controller/common"
	ingester_common "github.com/deepflowio/deepflow/server/ingester/profile/common"
	"github.com/deepflowio/deepflow/server/libs/utils"
	querier_common "github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	"github.com/deepflowio/deepflow/server/querier/profile/common"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
)

var log = logging.MustGetLogger("profile")
var InstanceProfileEventType = []string{"inuse_objects", "alloc_objects", "inuse_space", "alloc_space", "goroutines"}

func Tracing(args model.ProfileTracing, cfg *config.QuerierConfig) (result model.ProfileTree, debug interface{}, err error) {
	debugs := model.ProfileDebug{}
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
	sql := fmt.Sprintf(
		"SELECT %s, %s FROM %s WHERE %s LIMIT %d",
		common.PROFILE_LOCATION_STR, common.PROFILE_VALUE, common.TABLE_PROFILE, whereSql, limitSql,
	)

	if slices.Contains[[]string, string](InstanceProfileEventType, args.ProfileEventType) {
		timeSql := fmt.Sprintf(
			"SELECT time FROM %s WHERE %s ORDER BY time DESC LIMIT 1",
			common.TABLE_PROFILE, whereSql,
		)
		timeArgs := querier_common.QuerierParams{
			DB:      common.DATABASE_PROFILE,
			Sql:     timeSql,
			Debug:   strconv.FormatBool(args.Debug),
			Context: args.Context,
			ORGID:   args.OrgID,
		}
		timeEngine := &clickhouse.CHEngine{DB: common.DATABASE_PROFILE}
		timeEngine.Init()
		timeResult, timeDebug, timeError := timeEngine.ExecuteQuery(&timeArgs)
		if timeError != nil {
			log.Errorf("ExecuteQuery failed: %v", timeDebug, timeError)
			return
		}
		profileTimeDebug := model.Debug{}
		profileTimeDebug.Sql = timeSql
		profileTimeDebug.IP = timeDebug["ip"].(string)
		profileTimeDebug.QueryUUID = timeDebug["query_uuid"].(string)
		profileTimeDebug.SqlCH = timeDebug["sql"].(string)
		profileTimeDebug.Error = timeDebug["error"].(string)
		profileTimeDebug.QueryTime = timeDebug["query_time"].(string)
		debugs.QuerierDebug = append(debugs.QuerierDebug, profileTimeDebug)
		var timeValue int64
		timeValues := timeResult.Values
		for _, value := range timeValues {
			switch valueSlice := value.(type) {
			case []interface{}:
				if timeValueTime, ok := valueSlice[0].(time.Time); ok {
					timeValue = timeValueTime.Unix()
					break
				}
			}
		}
		if timeValue > 0 {
			sql = fmt.Sprintf(
				"SELECT %s, %s FROM %s WHERE %s AND time=%d LIMIT %d",
				common.PROFILE_LOCATION_STR, common.PROFILE_VALUE, common.TABLE_PROFILE, whereSql, timeValue, limitSql,
			)
		}

	}
	ckEngine := &clickhouse.CHEngine{DB: common.DATABASE_PROFILE}
	ckEngine.Init()
	querierArgs := querier_common.QuerierParams{
		DB:      common.DATABASE_PROFILE,
		Sql:     sql,
		Debug:   strconv.FormatBool(args.Debug),
		Context: args.Context,
		ORGID:   args.OrgID,
	}
	// XXX: change to streaming read, reduce memory
	querierResult, querierDebug, err := ckEngine.ExecuteQuery(&querierArgs)
	if err != nil {
		log.Errorf("ExecuteQuery failed: %v", querierDebug, err)
		return
	}

	profileDebug := NewProfileDebug(sql, querierDebug)
	debugs.QuerierDebug = append(debugs.QuerierDebug, profileDebug)

	formatStartTime := time.Now()
	profileLocationStrIndex := -1
	profileValueIndex := -1
	columns := querierResult.Columns
	values := querierResult.Values
	for columnIndex, col := range columns {
		switch column := col.(type) {
		case string:
			switch column {
			case "profile_location_str":
				profileLocationStrIndex = columnIndex
			case "profile_value":
				profileValueIndex = columnIndex
			}
		}
	}
	indexOK := slices.Contains[[]int, int]([]int{profileLocationStrIndex, profileValueIndex}, -1)
	if indexOK {
		log.Error("Not all fields found")
		err = errors.New("Not all fields found")
		return
	}

	// step 1: merge to uniq function stacks
	stackMap := make(map[string]int)
	profileLocationStrByte := []byte{}
	for _, value := range values {
		switch valueSlice := value.(type) {
		case []interface{}:
			if profileLocation, ok := valueSlice[profileLocationStrIndex].(string); ok {
				profileLocationStrByte, _ = ingester_common.ZstdDecompress(profileLocationStrByte, utils.Slice(profileLocation))
				// clip kernel function
				if *args.MaxKernelStackDepth != common.MAX_KERNEL_STACK_DEPTH_DEFAULT && args.ProfileLanguageType == common.LANGUAGE_TYPE_EBPF {
					profileLocationStrByte = ClipKernelFunction(profileLocationStrByte, *args.MaxKernelStackDepth)
				}
				profileLocationStr := string(profileLocationStrByte)
				profileValue := 0
				if profileValueInt, ok := valueSlice[profileValueIndex].(int); ok {
					profileValue = profileValueInt
				}
				if _, ok := stackMap[profileLocationStr]; ok {
					stackMap[profileLocationStr] += profileValue
				} else {
					stackMap[profileLocationStr] = profileValue
				}
			}
		}
	}

	// step 2: merge function stacks to profile tree
	rootTotalValue := 0
	// root function
	locations := []string{args.AppService}
	locationToID := map[string]int{args.AppService: 0}
	functionValues := [][]int{[]int{0, 0}}

	nodeUUIDToID := map[string]int{}
	functionColumns := []string{"self_value", "total_value"}
	nodeColumns := []string{"function_id", "parent_node_id", "self_value", "total_value"}

	rootNode := NewProfileTreeNode(0, 0, 0)
	nodes := []*model.ProfileTreeNode{rootNode}
	for profileLocationStr, profileValue := range stackMap {
		preSemicolonIndex := -1
		curSemicolonIndex := -1
		preID := -1
		// Non-leaf nodes profile_value value is 0
		nodeProfileValue := 0
		for runeIndex, r := range profileLocationStr {
			// Only leaf nodes profile_value have a value
			if runeIndex == len(profileLocationStr)-1 {
				curSemicolonIndex = len(profileLocationStr)
				nodeProfileValue = profileValue
				rootTotalValue += profileValue
			} else if r == rune(';') {
				// Non-leaf nodes
				curSemicolonIndex = runeIndex
				nodeProfileValue = 0
			}
			if curSemicolonIndex < 0 {
				continue
			}

			// Achieve the hash effect with uuid
			nodeUUID := controller_common.GenerateUUID(utils.String(utils.Slice(profileLocationStr)[:curSemicolonIndex]))
			// NodeUUID to id
			nodeID, ok := nodeUUIDToID[nodeUUID]
			if ok {
				existNode := nodes[nodeID]
				existNode.SelfValue += nodeProfileValue
				existNode.TotalValue = existNode.SelfValue
				preID = nodeID
			} else {
				// Location to id
				node := &model.ProfileTreeNode{}
				nodeID = len(nodes)
				nodeProfileLocationStrRef := utils.String(utils.Slice(profileLocationStr)[preSemicolonIndex+1 : curSemicolonIndex])
				locationID, ok := locationToID[nodeProfileLocationStrRef]
				if !ok {
					locationID = len(locations)
					locationToID[nodeProfileLocationStrRef] = locationID
					node = NewProfileTreeNode(locationID, nodeID, nodeProfileValue)
					locations = append(locations, nodeProfileLocationStrRef)
					functionValues = append(functionValues, []int{0, 0})
				} else {
					node = NewProfileTreeNode(locationID, nodeID, nodeProfileValue)
				}

				if preSemicolonIndex > 0 {
					node.ParentNodeID = preID
				}
				nodeUUIDToID[nodeUUID] = nodeID
				preID = nodeID
				nodes = append(nodes, node)
			}
			preSemicolonIndex = curSemicolonIndex
			curSemicolonIndex = -1
		}
	}

	if len(nodes) == 1 {
		formatEndTime := int64(time.Since(formatStartTime))
		formatTime := fmt.Sprintf("%.9fs", float64(formatEndTime)/1e9)
		debugs.FormatTime = formatTime
		debug = debugs
		return
	}

	// update total_value
	for _, node := range nodes {
		if node.SelfValue == 0 || node.ParentNodeID == -1 {
			continue
		}
		parentNode := nodes[node.ParentNodeID]
		UpdateNodeTotalValue(node, parentNode, nodes)
	}

	// format root node
	nodes[0].ParentNodeID = -1
	nodes[0].TotalValue = rootTotalValue

	// update function value and node value
	for _, node := range nodes {
		locationID := node.LocationID
		functionValues[locationID][0] += node.SelfValue
		functionValues[locationID][1] += node.TotalValue
		result.NodeValues.Values = append(result.NodeValues.Values, []int{locationID, node.ParentNodeID, node.SelfValue, node.TotalValue})
	}

	result.Functions = locations
	result.FunctionValues.Columns = functionColumns
	result.FunctionValues.Values = functionValues
	result.NodeValues.Columns = nodeColumns
	formatEndTime := int64(time.Since(formatStartTime))
	formatTime := fmt.Sprintf("%.9fs", float64(formatEndTime)/1e9)
	debugs.FormatTime = formatTime
	debug = debugs
	return
}

func NewProfileTreeNode(locationID int, nodeID int, profileValue int) *model.ProfileTreeNode {
	node := &model.ProfileTreeNode{}
	node.LocationID = locationID
	node.NodeID = nodeID
	node.SelfValue = profileValue
	node.TotalValue = profileValue
	return node
}

func UpdateNodeTotalValue(node *model.ProfileTreeNode, parentNode *model.ProfileTreeNode, nodes []*model.ProfileTreeNode) {
	parentNode.TotalValue += node.SelfValue
	if parentNode.ParentNodeID == -1 || parentNode.ParentNodeID == 0 {
		return
	}
	newParentNode := nodes[parentNode.ParentNodeID]
	UpdateNodeTotalValue(node, newParentNode, nodes)
}

func ClipKernelFunction(profileLocationByteSlice []byte, maxKernelStackDepth int) []byte {
	startIndex := 0
	sep := "[k]"
	clipIndex := len(profileLocationByteSlice)
	for layer := -1; layer < maxKernelStackDepth; layer++ {
		kernelFuncIndex := strings.Index(utils.String(profileLocationByteSlice[startIndex:]), sep)
		if kernelFuncIndex == -1 {
			break
		}
		startIndex += kernelFuncIndex
		clipIndex = startIndex
		startIndex += len(sep)
	}
	if clipIndex > 0 && clipIndex < len(profileLocationByteSlice) {
		clipIndex -= 1
	}
	return profileLocationByteSlice[:clipIndex]
}

func NewProfileDebug(sql string, querierDebug map[string]interface{}) (profileDebug model.Debug) {
	profileDebug.Sql = sql
	profileDebug.IP = querierDebug["ip"].(string)
	profileDebug.QueryUUID = querierDebug["query_uuid"].(string)
	profileDebug.SqlCH = querierDebug["sql"].(string)
	profileDebug.Error = querierDebug["error"].(string)
	profileDebug.QueryTime = querierDebug["query_time"].(string)
	return
}
