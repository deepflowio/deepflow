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

package router

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/genesis"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/manager"
)

type Debug struct {
	m *manager.Manager
	g *genesis.Genesis
}

func NewDebug(m *manager.Manager, g *genesis.Genesis) *Debug {
	return &Debug{m: m, g: g}
}

func (d *Debug) RegisterTo(e *gin.Engine) {
	e.GET("/v1/tasks/", getCloudBasicInfos(d.m))
	e.GET("/v1/tasks/:lcuuid/", getCloudBasicInfo(d.m))
	e.GET("/v1/info/:lcuuid/", getCloudResource(d.m))
	e.GET("/v1/genesis/:type/", getGenesisSyncData(d.g, true))
	e.GET("/v1/sync/:type/", getGenesisSyncData(d.g, false))
	e.GET("/v1/agent-stats/:vtapID/", getAgentStats(d.g))
	e.GET("/v1/genesis-storage/:vtapID/", getGenesisStorage(d.g))
	e.GET("/v1/kubernetes-refresh/", triggerKubernetesRefresh(d.m)) // TODO: Move to a better path
	e.GET("/v1/kubernetes-info/:clusterID/", getGenesisKubernetesData(d.g))
	e.GET("/v1/prometheus-info/:clusterID/", getGenesisPrometheusData(d.g))
	e.GET("/v1/sub-tasks/:lcuuid/", getKubernetesGatherBasicInfos(d.m))
	e.GET("/v1/kubernetes-gather-infos/:lcuuid/", getKubernetesGatherResources(d.m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/", getRecorderCache(d.m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/diff-bases/", getRecorderCacheDiffBaseDataSet(d.m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/tool-maps/", getRecorderCacheToolDataSet(d.m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/diff-bases/:resourceType/", getRecorderDiffBaseDataSetByResourceType(d.m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/diff-bases/:resourceType/:resourceLcuuid/", getRecorderDiffBase(d.m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/tool-maps/:field/", getRecorderCacheToolMap(d.m))
}

func getCloudBasicInfo(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]string)
		args["lcuuid"] = c.Param("lcuuid")
		data, err := service.GetCloudBasicInfos(args, m)
		JsonResponse(c, data, err)
	})
}

func getCloudBasicInfos(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetCloudBasicInfos(map[string]string{}, m)
		JsonResponse(c, data, err)
	})
}

func getCloudResource(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		data, err := service.GetCloudResource(lcuuid, m)
		JsonResponse(c, data, err)
	})
}

func getKubernetesGatherBasicInfos(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetKubernetesGatherBasicInfos(c.Param("lcuuid"), m)
		JsonResponse(c, data, err)
	})
}

func getKubernetesGatherResources(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetKubernetesGatherResources(c.Param("lcuuid"), m)
		JsonResponse(c, data, err)
	})
}

func getRecorderCache(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		data, err := service.GetRecorderDomainCache(domainLcuuid, subDomainLcuuid, m)
		JsonResponse(c, data, err)
	})
}

func getRecorderCacheDiffBaseDataSet(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		data, err := service.GetRecorderCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid, m)
		JsonResponse(c, data, err)
	})
}

func getRecorderCacheToolDataSet(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		data, err := service.GetRecorderCacheToolDataSet(domainLcuuid, subDomainLcuuid, m)
		JsonResponse(c, data, err)
	})
}

func getRecorderDiffBaseDataSetByResourceType(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		resourceType := c.Param("resourceType")
		data, err := service.GetRecorderDiffBaseDataSetByResourceType(domainLcuuid, subDomainLcuuid, resourceType, m)
		JsonResponse(c, data, err)
	})
}

func getRecorderDiffBase(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		resourceType := c.Param("resourceType")
		resourceLcuuid := c.Param("resourceLcuuid")
		data, err := service.GetRecorderDiffBaseByResourceLcuuid(domainLcuuid, subDomainLcuuid, resourceType, resourceLcuuid, m)
		JsonResponse(c, data, err)
	})
}

func getRecorderCacheToolMap(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		field := c.Param("field")
		data, err := service.GetRecorderToolMapByField(domainLcuuid, subDomainLcuuid, field, m)
		JsonResponse(c, data, err)
	})
}

func getAgentStats(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		orgID, err := GetContextOrgID(c)
		if err != nil {
			BadRequestResponse(c, httpcommon.ORG_ID_INVALID, err.Error())
			return
		}
		data, err := service.GetAgentStats(g, strconv.Itoa(orgID), c.Param("vtapID"))
		JsonResponse(c, data, err)
	})
}

func getGenesisStorage(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetGenesisAgentStorage(c.Param("vtapID"))
		JsonResponse(c, data, err)
	})
}

func getGenesisSyncData(g *genesis.Genesis, isLocal bool) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		orgID, err := GetContextOrgID(c)
		if err != nil {
			BadRequestResponse(c, httpcommon.ORG_ID_INVALID, err.Error())
			return
		}
		dataType := c.Param("type")
		var ret genesis.GenesisSyncDataResponse

		if isLocal {
			ret, err = service.GetGenesisData(orgID, g)
		} else {
			ret, err = service.GetGenesisSyncData(orgID, g)
		}

		var data interface{}

		switch dataType {
		case "vm":
			data = ret.VMs
		case "vpc":
			data = ret.VPCs
		case "host":
			data = ret.Hosts
		case "lldp":
			data = ret.Lldps
		case "port":
			data = ret.Ports
		case "network":
			data = ret.Networks
		case "ip":
			data = ret.IPLastSeens
		case "vinterface":
			data = ret.Vinterfaces
		case "process":
			data = ret.Processes
		case "vip":
			data = ret.VIPs
		default:
			err = errors.New("not found " + dataType + " data")
		}
		JsonResponse(c, data, err)
	})
}

func getGenesisKubernetesData(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		orgID, err := GetContextOrgID(c)
		if err != nil {
			BadRequestResponse(c, httpcommon.ORG_ID_INVALID, err.Error())
			return
		}
		data, err := service.GetGenesisKubernetesData(g, orgID, c.Param("clusterID"))
		JsonResponse(c, data, err)
	})
}

func getGenesisPrometheusData(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		orgID, err := GetContextOrgID(c)
		if err != nil {
			BadRequestResponse(c, httpcommon.ORG_ID_INVALID, err.Error())
			return
		}
		data, err := service.GetGenesisPrometheusData(g, orgID, c.Param("clusterID"))
		JsonResponse(c, data, err)
	})
}

func triggerKubernetesRefresh(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Query("domain_lcuuid")
		subDomainLcuuid := c.Query("sub_domain_lcuuid")
		versionString := c.Query("version")
		if domainLcuuid == "" || subDomainLcuuid == "" || versionString == "" {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "required parameter missing")
			return
		}
		version, err := strconv.Atoi(versionString)
		if err != nil {
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			return
		}
		err = service.TriggerKubernetesRefresh(domainLcuuid, subDomainLcuuid, version, m)
		JsonResponse(c, struct{}{}, err)
	})
}
