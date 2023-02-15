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

package router

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/genesis"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/manager"
)

func DebugRouter(e *gin.Engine, m *manager.Manager, g *genesis.Genesis) {
	e.GET("/v1/tasks/", getCloudBasicInfos(m))
	e.GET("/v1/tasks/:lcuuid/", getCloudBasicInfo(m))
	e.GET("/v1/info/:lcuuid/", getCloudResource(m))
	e.GET("/v1/genesis/:type/", getGenesisSyncData(g, true))
	e.GET("/v1/sync/:type/", getGenesisSyncData(g, false))
	e.GET("/v1/agent-stats/:ip/", getAgentStats(g))
	e.GET("/v1/kubernetes-info/:clusterID/", getGenesisKubernetesData(g))
	e.GET("/v1/sub-tasks/:lcuuid/", getKubernetesGatherBasicInfos(m))
	e.GET("/v1/kubernetes-gather-infos/:lcuuid/", getKubernetesGatherResources(m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/", getRecorderCache(m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/diff-bases/", getRecorderCacheDiffBaseDataSet(m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/tool-maps/", getRecorderCacheToolDataSet(m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/diff-bases/:resourceType/", getRecorderDiffBaseDataSetByResourceType(m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/diff-bases/:resourceType/:resourceLcuuid/", getRecorderDiffBase(m))
	e.GET("/v1/recorders/:domainLcuuid/:subDomainLcuuid/cache/tool-maps/:field/", getRecorderCacheToolMap(m))
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
		data, err := service.GetAgentStats(g, c.Param("ip"))
		JsonResponse(c, data, err)
	})
}

func getGenesisSyncData(g *genesis.Genesis, isLocal bool) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		dataType := c.Param("type")
		var ret genesis.GenesisSyncData
		var err error

		if isLocal {
			ret, err = service.GetGenesisData(g)
		} else {
			ret, err = service.GetGenesisSyncData(g)
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
		default:
			err = errors.New("not found " + dataType + " data")
		}
		JsonResponse(c, data, err)
	})
}

func getGenesisKubernetesData(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetGenesisKubernetesData(g, c.Param("clusterID"))
		JsonResponse(c, data, err)
	})
}
