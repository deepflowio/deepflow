package router

import (
	"server/controller/service/domain_configure"
	"github.com/gin-gonic/gin"
)

func DomainConfigRouter(e *gin.Engine) {
	e.GET("/v1/domains/:type/configure/", getDomainConfig)
}

func getDomainConfig(c *gin.Context) {
	var data interface{}
	var err error
	lcuuid := c.DefaultQuery("lcuuid", "")
	domainLcuuid := c.DefaultQuery("domain_lcuuid", "")
	if domainLcuuid != "" {
		data, err = domain_configure.GetSubDomainConfig(lcuuid, domainLcuuid)
	} else {
		data, err = domain_configure.GetDomainConfig(c.Param("type"), lcuuid)
	}
	JsonResponse(c, data, err)
}
