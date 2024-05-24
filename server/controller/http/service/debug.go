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

	gathermodel "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/manager"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func GetCloudBasicInfos(filter map[string]string, m *manager.Manager) (resp []cloudmodel.BasicInfo, err error) {
	var response []cloudmodel.BasicInfo

	if _, ok := filter["lcuuid"]; ok {
		if c, err := m.GetCloudInfo(filter["lcuuid"]); err == nil {
			response = append(response, c)
		}
	} else {
		for _, c := range m.GetCloudInfos() {
			response = append(response, c)
		}
	}
	return response, nil
}

func GetCloudResource(lcuuid string, m *manager.Manager) (resp cloudmodel.Resource, err error) {
	if c, err := m.GetCloudResource(lcuuid); err == nil {
		return c, nil
	} else {
		return cloudmodel.Resource{}, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("domain (%s) not found", lcuuid))
	}
}

func TriggerKubernetesRefresh(domainLcuuid, subDomainLcuuid string, version int, m *manager.Manager) error {
	return m.TriggerKubernetesRefresh(domainLcuuid, subDomainLcuuid, version)
}

func GetKubernetesGatherBasicInfos(lcuuid string, m *manager.Manager) (resp []gathermodel.KubernetesGatherBasicInfo, err error) {
	return m.GetKubernetesGatherBasicInfos(lcuuid)
}

func GetSubDomainResource(lcuuid, subDomainLcuuid string, m *manager.Manager) (resp cloudmodel.SubDomainResource, err error) {
	return m.GetSubDomainResource(lcuuid, subDomainLcuuid)
}

func GetKubernetesGatherResource(lcuuid, subDomainLcuuid string, m *manager.Manager) (resp gathermodel.KubernetesGatherResource, err error) {
	return m.GetKubernetesGatherResource(lcuuid, subDomainLcuuid)
}

func GetRecorderDomainCache(domainLcuuid, subDomainLcuuid string, m *manager.Manager) (resp cache.Cache, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		return recorder.GetCache(domainLcuuid, subDomainLcuuid), nil
	} else {
		return cache.Cache{}, NewError(httpcommon.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid string, m *manager.Manager) (resp diffbase.DataSet, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		return *recorder.GetCache(domainLcuuid, subDomainLcuuid).DiffBaseDataSet, nil
	} else {
		return diffbase.DataSet{}, NewError(httpcommon.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderCacheToolDataSet(domainLcuuid, subDomainLcuuid string, m *manager.Manager) (resp tool.DataSet, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		return *recorder.GetCache(domainLcuuid, subDomainLcuuid).ToolDataSet, nil
	} else {
		return tool.DataSet{}, NewError(httpcommon.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderDiffBaseDataSetByResourceType(domainLcuuid, subDomainLcuuid, resourceType string, m *manager.Manager) (resp map[string]interface{}, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		resp = recorder.GetCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid, resourceType)
		if resp == nil {
			return nil, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("recorder cache diff base data set of %s not found", resourceType))
		}
		return resp, nil
	} else {
		return map[string]interface{}{}, NewError(httpcommon.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderDiffBaseByResourceLcuuid(domainLcuuid, subDomainLcuuid, resourceType string, resourceLcuuid string, m *manager.Manager) (resp interface{}, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		resp = recorder.GetCacheDiffBase(domainLcuuid, subDomainLcuuid, resourceType, resourceLcuuid)
		if resp == nil {
			return nil, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("recorder cache diff base of %s %s not found", resourceType, resourceLcuuid))
		}
		return resp, nil
	} else {
		return map[string]interface{}{}, NewError(httpcommon.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderToolMapByField(domainLcuuid, subDomainLcuuid, field string, m *manager.Manager) (resp map[interface{}]interface{}, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		resp = recorder.GetToolMap(domainLcuuid, subDomainLcuuid, field)
		if resp == nil {
			return nil, NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("recorder tool map %s not found", field))
		}
		return resp, nil
	} else {
		return map[interface{}]interface{}{}, NewError(httpcommon.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetGenesisData(orgID int, g *genesis.Genesis) (genesis.GenesisSyncDataResponse, error) {
	return g.GetGenesisSyncData(orgID), nil
}

func GetGenesisSyncData(orgID int, g *genesis.Genesis) (genesis.GenesisSyncDataResponse, error) {
	return g.GetGenesisSyncResponse(orgID)
}

func GetGenesisKubernetesData(g *genesis.Genesis, orgID int, clusterID string) (map[string][]string, error) {
	return g.GetKubernetesResponse(orgID, clusterID)
}

func GetGenesisPrometheusData(g *genesis.Genesis, orgID int, clusterID string) ([]cloudmodel.PrometheusTarget, error) {
	return g.GetPrometheusResponse(orgID, clusterID)
}

func GetAgentStats(g *genesis.Genesis, orgID, vtapID string) (genesis.TridentStats, error) {
	return genesis.Synchronizer.GetAgentStats(orgID, vtapID)
}

func GetGenesisAgentStorage(vtapIDString string) (model.GenesisStorage, error) {
	var gStorage model.GenesisStorage
	vtapID, err := strconv.Atoi(vtapIDString)
	if err != nil {
		return gStorage, errors.New(fmt.Sprintf("invalid vtap id (%s)", vtapIDString))
	}
	err = mysql.Db.Where("vtap_id = ?", vtapID).First(&gStorage).Error
	return gStorage, err
}
