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
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/genesis"
	gcommon "github.com/deepflowio/deepflow/server/controller/genesis/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	routercommon "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/manager"
	"github.com/deepflowio/deepflow/server/controller/model"
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
	e.GET("/v1/trigger-domain/:lcuuid/", triggerDomain(d.m))
	e.GET("/v1/genesis/:type/", getGenesisSyncData(d.g, true))
	e.GET("/v1/sync/:type/", getGenesisSyncData(d.g, false))
	e.GET("/v1/agent-stats/:vtapID/", getAgentStats(d.g))
	e.GET("/v1/genesis-storage/:vtapID/", getGenesisStorage(d.g))
	e.GET("/v1/kubernetes-refresh/", triggerKubernetesRefresh(d.m)) // TODO: Move to a better path
	e.GET("/v1/kubernetes-info/:clusterID/", getGenesisKubernetesData(d.g))
	e.GET("/v1/sub-tasks/:lcuuid/", getKubernetesGatherBasicInfos(d.m))
	e.GET("/v1/sub-domain-info/:lcuuid/", getSubDomainResource(d.m))
	e.GET("/v1/kubernetes-gather-info/:lcuuid/", getKubernetesGatherResource(d.m))
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
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getCloudBasicInfos(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetCloudBasicInfos(map[string]string{}, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getCloudResource(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		data, err := service.GetCloudResource(lcuuid, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func triggerDomain(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		err := service.TriggerDomain(lcuuid, m)
		response.JSON(c, response.SetError(err))
	})
}

func getKubernetesGatherBasicInfos(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetKubernetesGatherBasicInfos(c.Param("lcuuid"), m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getSubDomainResource(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		db, err := routercommon.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		subDomainLcuuid := c.Param("lcuuid")
		var subDomain metadbmodel.SubDomain
		err = db.Where("lcuuid = ?", subDomainLcuuid).First(&subDomain).Error
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}
		data, err := service.GetSubDomainResource(subDomain.Domain, subDomainLcuuid, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getKubernetesGatherResource(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		db, err := routercommon.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		subDomainLcuuid := c.Param("lcuuid")
		var subDomain metadbmodel.SubDomain
		err = db.Where("lcuuid = ?", subDomainLcuuid).First(&subDomain).Error
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}
		data, err := service.GetKubernetesGatherResource(subDomain.Domain, subDomainLcuuid, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getRecorderCache(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		data, err := service.GetRecorderDomainCache(domainLcuuid, subDomainLcuuid, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getRecorderCacheDiffBaseDataSet(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		data, err := service.GetRecorderCacheDiffBaseDataSet(domainLcuuid, subDomainLcuuid, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getRecorderCacheToolDataSet(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		data, err := service.GetRecorderCacheToolDataSet(domainLcuuid, subDomainLcuuid, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getRecorderDiffBaseDataSetByResourceType(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		resourceType := c.Param("resourceType")
		data, err := service.GetRecorderDiffBaseDataSetByResourceType(domainLcuuid, subDomainLcuuid, resourceType, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getRecorderDiffBase(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		resourceType := c.Param("resourceType")
		resourceLcuuid := c.Param("resourceLcuuid")
		data, err := service.GetRecorderDiffBaseByResourceLcuuid(domainLcuuid, subDomainLcuuid, resourceType, resourceLcuuid, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getRecorderCacheToolMap(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Param("domainLcuuid")
		subDomainLcuuid := c.Param("subDomainLcuuid")
		field := c.Param("field")
		data, err := service.GetRecorderToolMapByField(domainLcuuid, subDomainLcuuid, field, m)
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getAgentStats(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		orgID, err := routercommon.GetContextOrgID(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.ORG_ID_INVALID), response.SetError(err))
			return
		}
		data, err := service.GetAgentStats(g, strconv.Itoa(orgID), c.Param("vtapID"))
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getGenesisStorage(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		db, err := routercommon.GetContextOrgDB(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.GET_ORG_DB_FAIL), response.SetError(err))
			return
		}
		data, err := service.GetGenesisAgentStorage(g.GetRedisStoreEnabled(), c.Param("vtapID"), db)
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getGenesisSyncData(g *genesis.Genesis, isLocal bool) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		orgID, err := routercommon.GetContextOrgID(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.ORG_ID_INVALID), response.SetError(err))
			return
		}
		dataType := c.Param("type")
		var ret gcommon.GenesisSyncDataResponse

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
			teamIDList := map[uint32]bool{}
			teamIDs, _ := c.GetQueryArray("team_id")
			for _, t := range teamIDs {
				teamID, err := strconv.Atoi(t)
				if err != nil {
					log.Warningf(err.Error())
					continue
				}
				teamIDList[uint32(teamID)] = false
			}

			filterType := c.Query("team_id_filter")
			switch filterType {
			case "":
				data = ret.Vinterfaces
			case "whitelist":
				retVinterfaces := []model.GenesisVinterface{}
				for _, v := range ret.Vinterfaces {
					if _, ok := teamIDList[v.TeamID]; !ok {
						continue
					}
					retVinterfaces = append(retVinterfaces, v)
				}
				data = retVinterfaces
			case "blacklist":
				retVinterfaces := []model.GenesisVinterface{}
				for _, v := range ret.Vinterfaces {
					if _, ok := teamIDList[v.TeamID]; ok {
						continue
					}
					retVinterfaces = append(retVinterfaces, v)
				}
				data = retVinterfaces
			default:
				err = fmt.Errorf("invalid team_id_filter (%s) for vinterface", filterType)
			}
		case "process":
			data = ret.Processes
		case "vip":
			data = ret.VIPs
		default:
			err = errors.New("not found " + dataType + " data")
		}
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func getGenesisKubernetesData(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		orgID, err := routercommon.GetContextOrgID(c)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.ORG_ID_INVALID), response.SetError(err))
			return
		}
		k8sEntries, err := service.GetGenesisKubernetesData(g, orgID, c.Param("clusterID"))
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.RESOURCE_NOT_FOUND), response.SetError(err))
			return
		}
		data := map[string][]string{}
		for key, entries := range k8sEntries {
			for _, entry := range entries {
				data[key] = append(data[key], string(entry))
			}
		}
		response.JSON(c, response.SetData(data), response.SetError(err))
	})
}

func triggerKubernetesRefresh(m *manager.Manager) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		domainLcuuid := c.Query("domain_lcuuid")
		subDomainLcuuid := c.Query("sub_domain_lcuuid")
		versionString := c.Query("version")
		if domainLcuuid == "" || subDomainLcuuid == "" || versionString == "" {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(fmt.Errorf("required parameter missing")))
			return
		}
		version, err := strconv.Atoi(versionString)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}
		err = service.TriggerKubernetesRefresh(domainLcuuid, subDomainLcuuid, version, m)
		response.JSON(c, response.SetError(err))
	})
}
