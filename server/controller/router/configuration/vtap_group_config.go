package configuration

import (
	"github.com/deepflowys/deepflow/server/controller/router"
	"github.com/deepflowys/deepflow/server/controller/service"
	"github.com/deepflowys/deepflow/server/controller/service/configuration"
	"github.com/gin-gonic/gin"
)

func vTapGroupConfigRouter(e *gin.Engine) {
	// TODO(weiqiang): remove
	e.GET("/v1/vtap/configuration/", getVTapGroupconfiguration)

	// TODO(weiqiang): removet "test" in url
	e.GET("/v1/vtap/configuration/test/", configuration.GetVTapGroupconfiguration)
}

// TODO(weiqiang): remove
func getVTapGroupconfiguration(c *gin.Context) {
	lcuuid, _ := c.GetQuery("lcuuid")
	data, err := service.GetVTapGroupConfiguration(lcuuid)
	router.JsonResponse(c, data, err)
}
