package configuration

import (
	"github.com/deepflowys/deepflow/server/controller/service/configuration"
	"github.com/gin-gonic/gin"
)

func vTapGroupConfigRouter(e *gin.Engine) {
	e.GET("/v1/vtap/configuration/", configuration.GetVTapGroupconfiguration)
}
