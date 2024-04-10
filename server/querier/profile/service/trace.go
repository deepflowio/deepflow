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
	querier_common "github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	"github.com/deepflowio/deepflow/server/querier/profile/common"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
)

var log = logging.MustGetLogger("profile")
var InstanceProfileEventType = []string{"inuse_objects", "alloc_objects", "inuse_space", "alloc_space", "goroutines"}

func Tracing(args model.ProfileTracing, cfg *config.QuerierConfig) (result []*model.ProfileTreeNode, debug interface{}, err error) {
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
	}
	// XXX: change to streaming read, reduce memory
	querierResult, querierDebug, err := ckEngine.ExecuteQuery(&querierArgs)
	if err != nil {
		log.Errorf("ExecuteQuery failed: %v", querierDebug, err)
		return
	}
	// XXX: move following line to a function
	profileDebug := model.Debug{}
	profileDebug.Sql = sql
	profileDebug.IP = querierDebug["ip"].(string)
	profileDebug.QueryUUID = querierDebug["query_uuid"].(string)
	profileDebug.SqlCH = querierDebug["sql"].(string)
	profileDebug.Error = querierDebug["error"].(string)
	profileDebug.QueryTime = querierDebug["query_time"].(string)
	debugs.QuerierDebug = append(debugs.QuerierDebug, profileDebug)

	formatStartTime := time.Now()
	profileLocationStrIndex := -1
	profileValueIndex := -1
	NodeIDToProfileTree := map[string]*model.ProfileTreeNode{}
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
	for _, value := range values {
		switch valueSlice := value.(type) {
		case []interface{}:
			profileLocationStr := ""
			if profileLocation, ok := valueSlice[profileLocationStrIndex].(string); ok {
				profileLocationStr = profileLocation
			}
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

	// step 2: merge function stacks to profile tree
	rootTotalValue := 0
	for profileLocationStr, profileValue := range stackMap {
		// XXX: reuse dst for every profileLocationStr
		dst := make([]byte, 0, len(profileLocationStr))
		profileLocationStrByte, _ := ingester_common.ZstdDecompress(dst, []byte(profileLocationStr))
		// XXX: reuse the memory of profileLocationStrByte
		profileLocationStrSlice := strings.Split(string(profileLocationStrByte), ";")
		for profileLocationIndex := range profileLocationStrSlice {
			nodeProfileValue := 0
			if profileLocationIndex == len(profileLocationStrSlice)-1 {
				nodeProfileValue = profileValue
				rootTotalValue += profileValue
			}
			// XXX: reuse the memory of profileLocationStrByte
			profileLocationStrs := strings.Join(profileLocationStrSlice[:profileLocationIndex+1], ";")
			nodeID := controller_common.GenerateUUID(profileLocationStrs)
			existNode, ok := NodeIDToProfileTree[nodeID]
			if ok {
				existNode.SelfValue += nodeProfileValue
				existNode.TotalValue = existNode.SelfValue
			} else {
				// XXX: After the aforementioned memory reuse optimization is completed, memory allocation is required here.
				nodeProfileLocationStr := profileLocationStrSlice[profileLocationIndex]
				node := NewProfileTreeNode(nodeProfileLocationStr, nodeID, nodeProfileValue)
				if profileLocationIndex != 0 {
					// XXX: reuse the memory of profileLocationStrByte
					parentProfileLocationStrs := strings.Join(profileLocationStrSlice[:profileLocationIndex], ";")
					node.ParentNodeID = controller_common.GenerateUUID(parentProfileLocationStrs)
				}
				NodeIDToProfileTree[nodeID] = node
			}
		}
	}

	if len(NodeIDToProfileTree) == 0 {
		return
	}

	// update total_value
	for _, node := range NodeIDToProfileTree {
		if node.SelfValue == 0 {
			continue
		}
		parentNode, ok := NodeIDToProfileTree[node.ParentNodeID]
		if ok {
			UpdateNodeTotalValue(node, parentNode, NodeIDToProfileTree)
		}

	}
	// format root node
	rootNode := NewProfileTreeNode("root", "", 0)
	rootNode.ParentNodeID = "-1"
	rootNode.TotalValue = rootTotalValue

	result = append(result, rootNode)
	for _, node := range NodeIDToProfileTree {
		result = append(result, node)
	}
	formatEndTime := int64(time.Since(formatStartTime))
	formatTime := fmt.Sprintf("%.9fs", float64(formatEndTime)/1e9)
	debugs.FormatTime = formatTime
	debug = debugs
	return
}

func NewProfileTreeNode(profileLocationStr string, nodeID string, profileValue int) *model.ProfileTreeNode {
	node := &model.ProfileTreeNode{}
	node.ProfileLocationStr = profileLocationStr
	node.NodeID = nodeID
	node.SelfValue = profileValue
	node.TotalValue = profileValue
	return node
}

func UpdateNodeTotalValue(node *model.ProfileTreeNode, parentNode *model.ProfileTreeNode, NodeIDToProfileTree map[string]*model.ProfileTreeNode) {
	parentNode.TotalValue += node.SelfValue
	if parentNode.ParentNodeID == "" {
		return
	}
	newParentNode, ok := NodeIDToProfileTree[parentNode.ParentNodeID]
	if ok {
		UpdateNodeTotalValue(node, newParentNode, NodeIDToProfileTree)
	}
}
