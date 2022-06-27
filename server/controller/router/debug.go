package router

import (
	"errors"
	"github.com/gin-gonic/gin"
	"server/controller/genesis"
	"server/controller/manager"
	"server/controller/service"
)

func DebugRouter(e *gin.Engine, m *manager.Manager, g *genesis.Genesis) {
	e.GET("/v1/tasks/", getCloudBasicInfos(m))
	e.GET("/v1/tasks/:lcuuid/", getCloudBasicInfo(m))
	e.GET("/v1/info/:lcuuid/", getCloudResource(m))
	e.GET("/v1/genesis/:type/", getGenesisData(g))
	e.GET("/v1/vinterfaces/", getGenesisVinterfacesData(g))
	e.GET("/v1/kubernetes-info/", getGenesisKubernetesData(g))
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

func getGenesisVinterfacesData(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetGenesisVinterfacesData(g)
		JsonResponse(c, data, err)
	})
}

func getGenesisKubernetesData(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetGenesisKubernetesData(g)
		JsonResponse(c, data, err)
	})
}

func getGenesisData(g *genesis.Genesis) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		dataType := c.Param("type")
		var data interface{}
		var err error
		switch dataType {
		case "ip":
			data, err = service.GetGenesisIPsData(g)
		case "subnet":
			data, err = service.GetGenesisSubnetsData(g)
		case "vm":
			data, err = service.GetGenesisVMsData(g)
		case "vpc":
			data, err = service.GetGenesisVPCsData(g)
		case "host":
			data, err = service.GetGenesisHostsData(g)
		case "lldp":
			data, err = service.GetGenesisLldpsData(g)
		case "port":
			data, err = service.GetGenesisPortsData(g)
		case "network":
			data, err = service.GetGenesisNetworksData(g)
		case "iplastseen":
			data, err = service.GetGenesisIPLastSeensData(g)
		default:
			err = errors.New("not found " + dataType + " data")
		}
		JsonResponse(c, data, err)
	})
}
