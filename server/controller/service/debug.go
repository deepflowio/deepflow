package service

import (
	"fmt"

	kubernetes_gather_model "github.com/metaflowys/metaflow/server/controller/cloud/kubernetes_gather/model"
	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/genesis"
	"github.com/metaflowys/metaflow/server/controller/manager"
	"github.com/metaflowys/metaflow/server/controller/model"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
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

func GetGenesisVinterfacesData(g *genesis.Genesis) ([]model.GenesisVinterface, error) {
	return g.GetVinterfacesData(), nil
}

func GetGenesisKubernetesData(g *genesis.Genesis) (map[string]genesis.KubernetesResponse, error) {
	return g.GetKubernetesData(), nil
}

func GetGenesisIPsData(g *genesis.Genesis) ([]cloudmodel.IP, error) {
	return g.GetIPsData(), nil
}

func GetGenesisSubnetsData(g *genesis.Genesis) ([]cloudmodel.Subnet, error) {
	return g.GetSubnetsData(), nil
}

func GetGenesisVMsData(g *genesis.Genesis) ([]model.GenesisVM, error) {
	return g.GetVMsData(), nil
}

func GetGenesisVPCsData(g *genesis.Genesis) ([]model.GenesisVpc, error) {
	return g.GetVPCsData(), nil
}

func GetGenesisHostsData(g *genesis.Genesis) ([]model.GenesisHost, error) {
	return g.GetHostsData(), nil
}

func GetGenesisLldpsData(g *genesis.Genesis) ([]model.GenesisLldp, error) {
	return g.GetLldpsData(), nil
}

func GetGenesisPortsData(g *genesis.Genesis) ([]model.GenesisPort, error) {
	return g.GetPortsData(), nil
}

func GetGenesisNetworksData(g *genesis.Genesis) ([]model.GenesisNetwork, error) {
	return g.GetNetworksData(), nil
}

func GetGenesisIPLastSeensData(g *genesis.Genesis) ([]model.GenesisIP, error) {
	return g.GetIPLastSeensData(), nil
}
