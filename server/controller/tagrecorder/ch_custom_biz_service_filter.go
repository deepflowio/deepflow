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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

/*
	{
	  "conditions":{
	    "RESOURCE_SETS":[
	      {
	        "id":"R100000",
	        "condition":[
	          {
	            "type":"tag",
	            "key":"chost",
	            "op":"=",
	            "rsType":"select",
	            "val":2
	          }
			]
	      }
		]
	  }
	}
*/

type Conditions struct {
	ResourceSets []ResourceSet `json:"RESOURCE_SETS"`
}

type ResourceSet struct {
	ID        string          `json:"id"`
	Condition []ConditionItem `json:"condition"`
}

type ConditionItem struct {
	Type   string      `json:"type"`
	Key    string      `json:"key"`
	Op     string      `json:"op"`
	RsType string      `json:"rsType"`
	Val    interface{} `json:"val"`
}

type ChCustomBizServiceFilter struct {
	UpdaterComponent[metadbmodel.ChCustomBizServiceFilter, IDKey]
}

func NewChCustomBizServiceFilter() *ChCustomBizServiceFilter {
	updater := &ChCustomBizServiceFilter{
		newUpdaterComponent[metadbmodel.ChCustomBizServiceFilter, IDKey](
			RESOURCE_TYPE_CH_CUSTOM_BIZ_SERVICE_FILTER,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (s *ChCustomBizServiceFilter) generateNewData(db *metadb.DB) (map[IDKey]metadbmodel.ChCustomBizServiceFilter, bool) {
	log.Infof("generate data for %s", s.resourceTypeName, db.LogPrefixORGID)
	keyToItem := make(map[IDKey]metadbmodel.ChCustomBizServiceFilter)
	if !s.cfg.DFWebService.Enabled {
		return keyToItem, true
	}
	body := make(map[string]interface{})
	bizRes, err := common.CURLPerform(
		"GET",
		fmt.Sprintf("http://%s:%d/v1/biz/all_svcs", s.cfg.DFWebService.Host, s.cfg.DFWebService.Port),
		body,
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", common.USER_TYPE_SUPER_ADMIN)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", common.USER_ID_SUPER_ADMIN)),
		common.WithHeader(common.HEADER_KEY_X_ORG_ID, fmt.Sprintf("%d", db.ORGID)),
	)
	if err != nil {
		log.Error(err, db.LogPrefixORGID)
		return nil, false
	}
	for i, _ := range bizRes.Get("DATA").MustArray() {
		bizData := bizRes.Get("DATA").GetIndex(i)
		bizType := bizData.Get("TYPE").MustInt()
		if bizType != CUSTOM_BIZ_SERVICE_TYPE {
			continue
		}
		tableName := bizData.Get("TABLE_NAME").MustString()
		tableNameSlice := strings.Split(tableName, ".")
		database := ""
		table := ""
		if len(tableNameSlice) >= 2 {
			database = tableNameSlice[0]
			table = tableNameSlice[1]
		} else {
			log.Errorf("tableName is illegal: %s", tableName, db.LogPrefixORGID)
			return nil, false
		}
		clientResourceSets := []ResourceSet{}
		clientBody := map[string]interface{}{}
		clientBody["conditions"] = &Conditions{}
		selects := map[string][]string{}
		selects["TAGS"] = []string{""}
		clientBody["selects"] = selects
		clientBody["db"] = database
		clientBody["tableName"] = table
		clientBody["paths"] = []map[string]string{}

		serverResourceSets := []ResourceSet{}
		serverBody := map[string]interface{}{}
		serverBody["conditions"] = &Conditions{}
		serverBody["selects"] = selects
		serverBody["db"] = database
		serverBody["tableName"] = table
		serverBody["paths"] = []map[string]string{}

		for j, _ := range bizData.Get("svcs").MustArray() {
			serviceData := bizData.Get("svcs").GetIndex(j)
			serviceID := serviceData.Get("ID").MustInt()
			reSetID := fmt.Sprintf("R%d", serviceID)
			if clientPaths, ok := clientBody["paths"].([]map[string]string); ok {
				clientBody["paths"] = append(clientPaths, map[string]string{"client": reSetID})
			}
			if serverPaths, ok := serverBody["paths"].([]map[string]string); ok {
				serverBody["paths"] = append(serverPaths, map[string]string{"server": reSetID})
			}

			// c
			for cIndex, _ := range serviceData.Get("SEARCH_PARAMS").Get("c").MustArray() {
				cParams := serviceData.Get("SEARCH_PARAMS").Get("c").GetIndex(cIndex)
				conditions := []ConditionItem{}
				for dIndex, _ := range cParams.Get("condition").MustArray() {
					cCondition := cParams.Get("condition").GetIndex(dIndex)
					cConditionBytes, marErr := cCondition.MarshalJSON()
					if marErr != nil {
						log.Error(marErr)
						return nil, false
					}
					var conditionItem ConditionItem
					jsonErr := json.Unmarshal(cConditionBytes, &conditionItem)
					if jsonErr != nil {
						log.Error(jsonErr)
						return nil, false
					}
					conditions = append(conditions, conditionItem)
				}
				if len(conditions) > 0 {
					cResourceSet := ResourceSet{}
					cResourceSet.ID = reSetID
					cResourceSet.Condition = conditions
					clientResourceSets = append(clientResourceSets, cResourceSet)
				}
			}
			// s
			for sIndex, _ := range serviceData.Get("SEARCH_PARAMS").Get("s").MustArray() {
				sParams := serviceData.Get("SEARCH_PARAMS").Get("s").GetIndex(sIndex)
				conditions := []ConditionItem{}
				for dIndex, _ := range sParams.Get("condition").MustArray() {
					sCondition := sParams.Get("condition").GetIndex(dIndex)
					sConditionBytes, marErr := sCondition.MarshalJSON()
					if marErr != nil {
						log.Error(marErr)
						return nil, false
					}
					var conditionItem ConditionItem
					jsonErr := json.Unmarshal(sConditionBytes, &conditionItem)
					if jsonErr != nil {
						log.Error(jsonErr)
						return nil, false
					}
					conditions = append(conditions, conditionItem)
				}
				if len(conditions) > 0 {
					sResourceSet := ResourceSet{}
					sResourceSet.ID = reSetID
					sResourceSet.Condition = conditions
					serverResourceSets = append(serverResourceSets, sResourceSet)
				}
			}
			// dual
			for dualIndex, _ := range serviceData.Get("SEARCH_PARAMS").Get("dual").MustArray() {
				dualParams := serviceData.Get("SEARCH_PARAMS").Get("dual").GetIndex(dualIndex)
				conditions := []ConditionItem{}
				for dIndex, _ := range dualParams.Get("condition").MustArray() {
					dualCondition := dualParams.Get("condition").GetIndex(dIndex)
					dualConditionBytes, marErr := dualCondition.MarshalJSON()
					if marErr != nil {
						log.Error(marErr)
						return nil, false
					}
					var conditionItem ConditionItem
					jsonErr := json.Unmarshal(dualConditionBytes, &conditionItem)
					if jsonErr != nil {
						log.Error(jsonErr)
						return nil, false
					}
					conditions = append(conditions, conditionItem)
				}
				if len(conditions) > 0 {
					dualResourceSet := ResourceSet{}
					dualResourceSet.ID = reSetID
					dualResourceSet.Condition = conditions
					clientResourceSets = append(clientResourceSets, dualResourceSet)
					serverResourceSets = append(serverResourceSets, dualResourceSet)
				}
			}
		}

		clientConditions := map[string][]ResourceSet{}
		clientConditions["RESOURCE_SETS"] = clientResourceSets
		clientBody["conditions"] = clientConditions

		serverConditions := map[string][]ResourceSet{}
		serverConditions["RESOURCE_SETS"] = serverResourceSets
		serverBody["conditions"] = serverConditions
		log.Infof("clientbody: %+v", clientBody)
		log.Infof("serverbody: %+v", serverBody)
		// client
		clientRes, clientErr := common.CURLPerform(
			"POST",
			fmt.Sprintf("http://%s:%d/querier-params", s.cfg.QuerierJSService.Host, s.cfg.QuerierJSService.Port),
			clientBody,
		)
		if clientErr != nil {
			log.Error(clientErr, db.LogPrefixORGID)
			return nil, false
		}
		for k, _ := range clientRes.Get("DATA").Get("path").MustArray() {
			query := clientRes.Get("DATA").Get("path").GetIndex(k)
			queryID := query.GetPath("sql", "QUERY_ID").MustString()
			queryIDSlice := strings.Split(queryID, "-")
			serviceIDStr := strings.TrimPrefix(queryIDSlice[0], "R")
			serviceIDInt, err := strconv.Atoi(serviceIDStr)
			if err != nil {
				log.Error(err, db.LogPrefixORGID)
				return nil, false
			}
			clientFilter := query.GetPath("sql", "WHERE").MustString()
			serviceFilter, ok := keyToItem[IDKey{ID: serviceIDInt}]
			if ok {
				serviceFilter.ClientFilter = clientFilter
			} else {
				keyToItem[IDKey{ID: serviceIDInt}] = metadbmodel.ChCustomBizServiceFilter{
					ID:           serviceIDInt,
					ClientFilter: clientFilter,
				}
			}
		}

		// server
		serverRes, serverErr := common.CURLPerform(
			"POST",
			fmt.Sprintf("http://%s:%d/querier-params", s.cfg.QuerierJSService.Host, s.cfg.QuerierJSService.Port),
			serverBody,
		)
		if serverErr != nil {
			log.Error(serverErr, db.LogPrefixORGID)
			return nil, false
		}
		for l, _ := range serverRes.Get("DATA").Get("path").MustArray() {
			query := serverRes.Get("DATA").Get("path").GetIndex(l)
			queryID := query.GetPath("sql", "QUERY_ID").MustString()
			queryIDSlice := strings.Split(queryID, "-")
			serviceIDStr := strings.TrimPrefix(queryIDSlice[0], "R")
			serviceIDInt, err := strconv.Atoi(serviceIDStr)
			if err != nil {
				log.Error(err, db.LogPrefixORGID)
				return nil, false
			}
			serverFilter := query.GetPath("sql", "WHERE").MustString()
			serviceFilter, ok := keyToItem[IDKey{ID: serviceIDInt}]
			if ok {
				serviceFilter.ServerFilter = serverFilter
			} else {
				keyToItem[IDKey{ID: serviceIDInt}] = metadbmodel.ChCustomBizServiceFilter{
					ID:           serviceIDInt,
					ServerFilter: serverFilter,
				}
			}
		}
	}
	return keyToItem, true
}

func (s *ChCustomBizServiceFilter) generateKey(dbItem metadbmodel.ChCustomBizServiceFilter) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (s *ChCustomBizServiceFilter) generateUpdateInfo(oldItem, newItem metadbmodel.ChCustomBizServiceFilter) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.ClientFilter != newItem.ClientFilter {
		updateInfo["client_filter"] = newItem.ClientFilter
	}
	if oldItem.ServerFilter != newItem.ServerFilter {
		updateInfo["server_filter"] = newItem.ServerFilter
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
