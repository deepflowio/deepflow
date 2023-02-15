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
	"fmt"

	kubernetes_gather_model "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/manager"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
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
		return cloudmodel.Resource{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("domain (%s) not found", lcuuid))
	}
}

func GetKubernetesGatherBasicInfos(lcuuid string, m *manager.Manager) (resp []kubernetes_gather_model.KubernetesGatherBasicInfo, err error) {
	response, err := m.GetKubernetesGatherBasicInfos(lcuuid)
	return response, err
}

func GetKubernetesGatherResources(lcuuid string, m *manager.Manager) (resp []kubernetes_gather_model.KubernetesGatherResource, err error) {
	response, err := m.GetKubernetesGatherResources(lcuuid)
	return response, err
}

func GetRecorderDomainCache(domainLcuuid, subDomainLcuuid string, m *manager.Manager) (resp cache.Cache, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		return recorder.GetCache(domainLcuuid, subDomainLcuuid), nil
	} else {
		return cache.Cache{}, NewError(common.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid string, m *manager.Manager) (resp cache.DiffBaseDataSet, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		return recorder.GetCache(domainLcuuid, subDomainLcuuid).DiffBaseDataSet, nil
	} else {
		return cache.DiffBaseDataSet{}, NewError(common.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderCacheToolDataSet(domainLcuuid, subDomainLcuuid string, m *manager.Manager) (resp cache.ToolDataSet, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		return recorder.GetCache(domainLcuuid, subDomainLcuuid).ToolDataSet, nil
	} else {
		return cache.ToolDataSet{}, NewError(common.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderDiffBaseDataSetByResourceType(domainLcuuid, subDomainLcuuid, resourceType string, m *manager.Manager) (resp map[string]interface{}, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		resp = recorder.GetCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid, resourceType)
		if resp == nil {
			return nil, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("recorder cache diff base data set of %s not found", resourceType))
		}
		return resp, nil
	} else {
		return map[string]interface{}{}, NewError(common.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderDiffBaseByResourceLcuuid(domainLcuuid, subDomainLcuuid, resourceType string, resourceLcuuid string, m *manager.Manager) (resp interface{}, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		resp = recorder.GetCacheDiffBase(domainLcuuid, subDomainLcuuid, resourceType, resourceLcuuid)
		if resp == nil {
			return nil, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("recorder cache diff base of %s %s not found", resourceType, resourceLcuuid))
		}
		return resp, nil
	} else {
		return map[string]interface{}{}, NewError(common.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetRecorderToolMapByField(domainLcuuid, subDomainLcuuid, field string, m *manager.Manager) (resp map[interface{}]interface{}, err error) {
	if recorder, err := m.GetRecorder(domainLcuuid); err == nil {
		resp = recorder.GetToolMap(domainLcuuid, subDomainLcuuid, field)
		if resp == nil {
			return nil, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("recorder tool map %s not found", field))
		}
		return resp, nil
	} else {
		return map[interface{}]interface{}{}, NewError(common.RESOURCE_NOT_FOUND, err.Error())
	}
}

func GetGenesisData(g *genesis.Genesis) (genesis.GenesisSyncData, error) {
	return g.GetGenesisSyncData(), nil
}

func GetGenesisSyncData(g *genesis.Genesis) (genesis.GenesisSyncData, error) {
	return g.GetGenesisSyncResponse()
}

func GetGenesisKubernetesData(g *genesis.Genesis, clusterID string) (map[string][]string, error) {
	data, err := g.GetKubernetesResponse(clusterID)
	return data, err
}

func GetAgentStats(g *genesis.Genesis, ip string) ([]genesis.TridentStats, error) {
	return genesis.Synchronizer.GetAgentStats(ip), nil
}
