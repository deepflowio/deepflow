package router

import (
	"github.com/gin-gonic/gin"

	"server/controller/config"
	"server/controller/service"
)

func VTapInterface(e *gin.Engine, cfg *config.ControllerConfig) {
	e.GET("/v1/vtap-interfaces/", getVTapInterfaces)
}

func getVTapInterfaces(c *gin.Context) {
	args := make(map[string]interface{})
	data, err := service.GetVTapInterfaces(args)
	JsonResponse(c, data, err)
}
