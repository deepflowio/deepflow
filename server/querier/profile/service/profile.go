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
	"slices"
	"strconv"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	controller_common "github.com/deepflowio/deepflow/server/controller/common"
	ingester_common "github.com/deepflowio/deepflow/server/ingester/profile/common"
	"github.com/deepflowio/deepflow/server/libs/utils"
	querier_common "github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	"github.com/deepflowio/deepflow/server/querier/profile/common"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
)

var log = logging.MustGetLogger("profile")
var InstanceProfileEventType = []string{"inuse_objects", "inuse_space", "goroutines", "mem-inuse"}

const (
	initLocationCapacity = 1024
	initNodeCapacity     = 8192
)

func GetAppService(args model.Profile, where string, debugs model.ProfileDebug) ([]string, model.ProfileDebug, error) {
	sql := fmt.Sprintf(
		"SELECT app_service FROM %s WHERE %s GROUP BY app_service LIMIT 11",
		common.TABLE_PROFILE, where,
	)
	ckEngine := &clickhouse.CHEngine{DB: common.DATABASE_PROFILE}
	ckEngine.Init()
	querierArgs := querier_common.QuerierParams{
		DB:      common.DATABASE_PROFILE,
		Sql:     sql,
		Debug:   strconv.FormatBool(args.Debug),
		Context: args.Context,
		ORGID:   args.OrgID,
	}

	querierResult, querierDebug, err := ckEngine.ExecuteQuery(&querierArgs)
	profileDebug := NewProfileDebug(sql, querierDebug)
	debugs.QuerierDebug = append(debugs.QuerierDebug, profileDebug)
	appServices := []string{}
	if err != nil {
		log.Errorf("ExecuteQuery failed: %v", querierDebug, err)
		return appServices, debugs, err
	}
	values := querierResult.Values
	for _, value := range values {
		switch valueSlice := value.(type) {
		case []interface{}:
			appService, ok := valueSlice[0].(string)
			if ok {
				appServices = append(appServices, appService)
			}
		}
	}
	return appServices, debugs, nil
}

func Profile(args model.Profile, cfg *config.QuerierConfig) (model.ProfileTree, interface{}, error) {
	whereSlice := []string{}
	whereSlice = append(whereSlice, fmt.Sprintf(" time>=%d", args.TimeStart))
	whereSlice = append(whereSlice, fmt.Sprintf(" time<=%d", args.TimeEnd))
	if args.AppService != "" {
		whereSlice = append(whereSlice, fmt.Sprintf(" app_service='%s'", args.AppService))
	}
	whereSlice = append(whereSlice, fmt.Sprintf(" profile_language_type='%s'", args.ProfileLanguageType))
	whereSlice = append(whereSlice, fmt.Sprintf(" profile_event_type='%s'", args.ProfileEventType))
	if args.TagFilter != "" {
		whereSlice = append(whereSlice, " ("+args.TagFilter+")")
	}
	whereSql := strings.Join(whereSlice, " AND")
	debugs := model.ProfileDebug{}
	if args.AppService == "" {
		appServices, appDebugs, err := GetAppService(args, whereSql, debugs)
		debugs = appDebugs
		if err != nil {
			log.Errorf("GetAppService failed: %v", err)
			return model.ProfileTree{}, debugs, err
		}
		if len(appServices) < 1 || len(appServices) > 10 {
			return model.ProfileTree{}, debugs, fmt.Errorf("app_service count %d is invalid", len(appServices))
		}
		args.AppService = strings.Join(appServices, ", ")
	}
	return GenerateProfile(args, cfg, whereSql, debugs)
}

func GenerateProfile(args model.Profile, cfg *config.QuerierConfig, where string, debugs model.ProfileDebug) (result model.ProfileTree, debug interface{}, err error) {
	limitSql := cfg.Profile.FlameQueryLimit
	sql := fmt.Sprintf(
		"SELECT %s, %s FROM %s WHERE %s LIMIT %d",
		common.PROFILE_LOCATION_STR, common.PROFILE_VALUE, common.TABLE_PROFILE, where, limitSql,
	)

	if slices.Contains[[]string, string](InstanceProfileEventType, args.ProfileEventType) {
		sql = fmt.Sprintf(
			"SELECT %s, Last(%s) AS %s FROM %s WHERE %s GROUP BY %s ,%s, %s LIMIT %d",
			common.PROFILE_LOCATION_STR, common.PROFILE_VALUE, common.PROFILE_VALUE, common.TABLE_PROFILE, where, common.PROFILE_LOCATION_STR, common.TAG_AGENT_ID, common.TAG_PROCESS_ID, limitSql,
		)
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
	profileDebug := NewProfileDebug(sql, querierDebug)
	debugs.QuerierDebug = append(debugs.QuerierDebug, profileDebug)
	if err != nil {
		log.Errorf("ExecuteQuery failed: %v", querierDebug, err)
		debug = debugs
		return
	}

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
		debug = debugs
		return
	}

	// root function
	locations := make([]string, 0, initLocationCapacity)
	locations = append(locations, args.AppService)
	locationToID := map[string]int{args.AppService: 0}

	nodeUUIDToID := make(map[string]int)
	stackToNodeID := make(map[string]int)
	nodes := make([]model.ProfileTreeNode, 0, initNodeCapacity)
	nodes = append(nodes, model.ProfileTreeNode{ParentNodeID: -1})

	// merge function stacks to profile tree
	profileLocationStrByte := []byte{}
	for _, value := range values {
		// 1. extract function stack
		profileLocationCompress := ""
		var profileValue int
		var ok bool
		switch valueSlice := value.(type) {
		case []interface{}:
			if profileLocationCompress, ok = valueSlice[profileLocationStrIndex].(string); !ok {
				continue
			}
			profileValuePtr, ok := valueSlice[profileValueIndex].(int64)
			if !ok {
				continue
			} else {
				profileValue = int(profileValuePtr)
			}
		}

		// 2. check the entier compressed stack
		if nodeID, ok := stackToNodeID[profileLocationCompress]; ok {
			updateAllParentNodes(nodes, nodeID, profileValue, profileValue)
			continue
		}

		// 3. decompress & cut kernel function
		profileLocationStrByte, _ = ingester_common.ZstdDecompress(profileLocationStrByte, utils.Slice(profileLocationCompress))
		if *args.MaxKernelStackDepth != common.MAX_KERNEL_STACK_DEPTH_DEFAULT && args.ProfileLanguageType == common.LANGUAGE_TYPE_EBPF {
			cutted := false
			// cut kernel functions
			profileLocationStrByte, cutted = CutKernelFunction(profileLocationStrByte, *args.MaxKernelStackDepth, "[k]")
			if !cutted {
				// cut cuda functions
				profileLocationStrByte, _ = CutKernelFunction(profileLocationStrByte, *args.MaxKernelStackDepth, "[c]")
			}
		}

		// 4. merge to profile tree
		preSemicolonIndex := len(profileLocationStrByte)
		curSemicolonIndex := -2
		preNodeID := -1
		nodeProfileValue := profileValue
		for runeIndex := len(profileLocationStrByte) - 1; runeIndex >= 0; runeIndex -= 1 {
			if runeIndex == 0 {
				curSemicolonIndex = -1
			} else if profileLocationStrByte[runeIndex] == byte(';') {
				curSemicolonIndex = runeIndex
			} else {
				continue
			}
			if preNodeID >= 0 { // Only leaf node has the selfValue
				nodeProfileValue = 0
			}

			// Achieve the hash effect with uuid
			nodeUUID := controller_common.GenerateUUID(utils.String(profileLocationStrByte[:preSemicolonIndex]))
			nodeID, ok := nodeUUIDToID[nodeUUID]
			if ok {
				// son node
				if preNodeID >= 0 {
					nodes[preNodeID].ParentNodeID = nodeID
				}
				updateAllParentNodes(nodes, nodeID, nodeProfileValue, profileValue)
				break
			} else {
				// Location to id
				nodeProfileLocationStrRef := utils.String(profileLocationStrByte[curSemicolonIndex+1 : preSemicolonIndex])
				locationID, ok := locationToID[nodeProfileLocationStrRef]
				if !ok {
					locationID = len(locations)
					nodeProfileLocationStr := string(profileLocationStrByte[curSemicolonIndex+1 : preSemicolonIndex])
					locationToID[nodeProfileLocationStr] = locationID
					locations = append(locations, nodeProfileLocationStr)
				}

				// new node
				nodeID = len(nodes)
				nodeUUIDToID[nodeUUID] = nodeID
				nodes = append(nodes, newProfileTreeNode(locationID, nodeProfileValue, profileValue))
				if runeIndex == 0 {
					nodes[0].TotalValue += profileValue // update root
				}

				if preNodeID >= 0 {
					nodes[preNodeID].ParentNodeID = nodeID
				} else {
					// remember the entier stack
					stackToNodeID[profileLocationCompress] = nodeID // compressed stack
				}
			}
			preSemicolonIndex = curSemicolonIndex
			preNodeID = nodeID
		}
	}

	if len(nodes) == 1 {
		formatEndTime := int64(time.Since(formatStartTime))
		formatTime := fmt.Sprintf("%.9fs", float64(formatEndTime)/1e9)
		debugs.FormatTime = formatTime
		debug = debugs
		return
	}

	// calculate function value and node value
	result.FunctionValues.Values = make([][]int, len(locations))
	for i := range result.FunctionValues.Values {
		result.FunctionValues.Values[i] = []int{0, 0}
	}
	result.NodeValues.Values = make([][]int, 0, len(nodes))
	for _, node := range nodes {
		locationID := node.LocationID
		result.FunctionValues.Values[locationID][0] += node.SelfValue
		result.FunctionValues.Values[locationID][1] += node.TotalValue
		result.NodeValues.Values = append(result.NodeValues.Values, []int{locationID, node.ParentNodeID, node.SelfValue, node.TotalValue})
	}

	result.Functions = locations
	locationTypes := GetLocationType(locations, result.FunctionValues.Values, args.ProfileEventType)
	result.FunctionTypes = locationTypes
	result.FunctionValues.Columns = []string{"self_value", "total_value"}
	result.NodeValues.Columns = []string{"function_id", "parent_node_id", "self_value", "total_value"}
	formatEndTime := int64(time.Since(formatStartTime))
	formatTime := fmt.Sprintf("%.9fs", float64(formatEndTime)/1e9)
	debugs.FormatTime = formatTime
	debug = debugs
	return
}

func newProfileTreeNode(locationID, selfValue, totalValue int) model.ProfileTreeNode {
	node := model.ProfileTreeNode{}
	node.LocationID = locationID
	node.SelfValue = selfValue
	node.TotalValue = totalValue
	return node
}

func updateAllParentNodes(nodes []model.ProfileTreeNode, thisNodeID, selfValue, totalValue int) {
	// leaf node
	thisNode := &nodes[thisNodeID]
	thisNode.SelfValue += selfValue
	thisNode.TotalValue += totalValue

	// parent nodes
	for thisNode.ParentNodeID >= 0 {
		thisNode = &nodes[thisNode.ParentNodeID]
		thisNode.TotalValue += totalValue
	}

}

func CutKernelFunction(profileLocationByteSlice []byte, maxKernelStackDepth int, sep string) ([]byte, bool) {
	startIndex := 0
	cutted := true
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
	} else {
		cutted = false
	}
	return profileLocationByteSlice[:clipIndex], cutted
}

func NewProfileDebug(sql string, querierDebug map[string]interface{}) (profileDebug model.Debug) {
	profileDebug.Sql = sql
	if querierDebug != nil {
		qDebug := querierDebug["query_sqls"].([]client.Debug)[0]
		profileDebug.IP = qDebug.IP
		profileDebug.QueryUUID = qDebug.QueryUUID
		profileDebug.SqlCH = qDebug.Sql
		profileDebug.Error = qDebug.Error
		profileDebug.QueryTime = qDebug.QueryTime
	}
	return
}

func GetLocationType(locations []string, locationValues [][]int, profileEventType string) []string {
	locationTypes := make([]string, len(locations))
	for i, location := range locations {
		if locationValues[i][0] == locationValues[i][1] && strings.HasPrefix(profileEventType, "mem-") { // leaf node && memory profile
			locationTypes[i] = "O" // object type
		} else if i == 0 { // root node
			if location != "Total" {
				locationTypes[i] = "P" // process
			} else {
				locationTypes[i] = "H" // host
			}
		} else {
			hasLocationType := false
			for preffix, locatonType := range common.LOCATION_TYPE_MAP {
				if strings.HasPrefix(location, preffix) {
					locationTypes[i] = locatonType
					hasLocationType = true
					break
				}
			}
			if !hasLocationType {
				if strings.HasPrefix(location, "[") {
					locationTypes[i] = "?" // unknown
				} else {
					locationTypes[i] = "A" // application function
				}
			}
		}
	}
	return locationTypes
}
