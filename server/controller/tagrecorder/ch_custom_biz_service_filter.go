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
	"fmt"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

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
		svcs := bizData.Get("svcs").MustArray()
		if bizType != CUSTOM_BIZ_SERVICE_TYPE {
			continue
		}
		if len(svcs) == 0 {
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

		clientResourceSets := []map[string]interface{}{}
		clientPaths := []map[string]interface{}{}
		serverResourceSets := []map[string]interface{}{}
		serverPaths := []map[string]interface{}{}

		for j, _ := range svcs {
			serviceData := bizData.Get("svcs").GetIndex(j)
			serviceID := serviceData.Get("ID").MustInt()
			reSetID := fmt.Sprintf("R%d", serviceID)

			// c
			for cIndex, _ := range serviceData.Get("SEARCH_PARAMS").Get("c").MustArray() {
				cParams := serviceData.Get("SEARCH_PARAMS").Get("c").GetIndex(cIndex)
				conditions := []map[string]interface{}{}
				for dIndex, _ := range cParams.Get("condition").MustArray() {
					cCondition := cParams.Get("condition").GetIndex(dIndex).MustMap()
					conditions = append(conditions, cCondition)
				}
				if len(conditions) > 0 {
					cResourceSet := map[string]interface{}{}
					cResourceSet["id"] = reSetID
					cResourceSet["condition"] = conditions
					clientResourceSets = append(clientResourceSets, cResourceSet)
					clientPaths = append(clientPaths, map[string]interface{}{"client": reSetID})
				}
			}
			// s
			for sIndex, _ := range serviceData.Get("SEARCH_PARAMS").Get("s").MustArray() {
				sParams := serviceData.Get("SEARCH_PARAMS").Get("s").GetIndex(sIndex)
				conditions := []map[string]interface{}{}
				for dIndex, _ := range sParams.Get("condition").MustArray() {
					sCondition := sParams.Get("condition").GetIndex(dIndex).MustMap()
					conditions = append(conditions, sCondition)
				}
				if len(conditions) > 0 {
					sResourceSet := map[string]interface{}{}
					sResourceSet["id"] = reSetID
					sResourceSet["condition"] = conditions
					serverResourceSets = append(serverResourceSets, sResourceSet)
					serverPaths = append(serverPaths, map[string]interface{}{"server": reSetID})
				}
			}
			// dual
			for dualIndex, _ := range serviceData.Get("SEARCH_PARAMS").Get("dual").MustArray() {
				dualParams := serviceData.Get("SEARCH_PARAMS").Get("dual").GetIndex(dualIndex)
				conditions := []map[string]interface{}{}
				for dIndex, _ := range dualParams.Get("condition").MustArray() {
					dualCondition := dualParams.Get("condition").GetIndex(dIndex).MustMap()
					conditions = append(conditions, dualCondition)
				}
				if len(conditions) > 0 {
					dualResourceSet := map[string]interface{}{}
					dualResourceSet["id"] = reSetID
					dualResourceSet["condition"] = conditions
					clientResourceSets = append(clientResourceSets, dualResourceSet)
					serverResourceSets = append(serverResourceSets, dualResourceSet)
					clientPaths = append(clientPaths, map[string]interface{}{"client": reSetID})
					serverPaths = append(serverPaths, map[string]interface{}{"server": reSetID})
				}
			}
		}
		// client
		if len(clientResourceSets) > 0 {
			clientBody := map[string]interface{}{
				"conditions": map[string]interface{}{
					"RESOURCE_SETS": clientResourceSets,
				},
				"selects": map[string]interface{}{
					"TAGS": []interface{}{""},
				},
				"tableName": table,
				"paths":     clientPaths,
				"db":        database,
			}
			clientRes, clientErr := common.CURLPerform(
				"POST",
				fmt.Sprintf("http://%s:%d/create-business-sql", s.cfg.QuerierJSService.Host, s.cfg.QuerierJSService.Port),
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
					keyToItem[IDKey{ID: serviceIDInt}] = serviceFilter
				} else {
					keyToItem[IDKey{ID: serviceIDInt}] = metadbmodel.ChCustomBizServiceFilter{
						ID:           serviceIDInt,
						ClientFilter: clientFilter,
					}
				}
			}
		}
		// server
		if len(serverResourceSets) > 0 {
			serverBody := map[string]interface{}{
				"conditions": map[string]interface{}{
					"RESOURCE_SETS": serverResourceSets,
				},
				"selects": map[string]interface{}{
					"TAGS": []interface{}{""},
				},
				"tableName": table,
				"paths":     serverPaths,
				"db":        database,
			}
			serverRes, serverErr := common.CURLPerform(
				"POST",
				fmt.Sprintf("http://%s:%d/create-business-sql", s.cfg.QuerierJSService.Host, s.cfg.QuerierJSService.Port),
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
					keyToItem[IDKey{ID: serviceIDInt}] = serviceFilter
				} else {
					keyToItem[IDKey{ID: serviceIDInt}] = metadbmodel.ChCustomBizServiceFilter{
						ID:           serviceIDInt,
						ServerFilter: serverFilter,
					}
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
