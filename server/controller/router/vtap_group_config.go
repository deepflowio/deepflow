package router

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"server/controller/model"
	"server/controller/service"
)

func VTapGroupConfigRouter(e *gin.Engine) {
	e.POST("/v1/vtap-group-configurations/", createVTapGroupConfig)
	e.DELETE("/v1/vtap-group-configurations/:lcuuid/", deleteVTapGroupConfig)
	e.PATCH("/v1/vtap-group-configurations/:lcuuid/", updateVTapGroupConfig)
	e.GET("/v1/vtap-group-configurations/", getVTapGroupConfigs)
	e.GET("/v1/vtap-group-configuration/detailed/:lcuuid/", getVTapGroupDetailedConfig)
	e.GET("/v1/vtap-group-configuration/advanced/:lcuuid/", getVTapGroupAdvancedConfig)
	e.PATCH("/v1/vtap-group-configuration/advanced/:lcuuid/", updateVTapGroupAdvancedConfig)
}

func createVTapGroupConfig(c *gin.Context) {
	vTapGroupConfig := &model.VTapGroupConfiguration{}
	c.ShouldBindBodyWith(&vTapGroupConfig, binding.JSON)
	data, err := service.CreateVTapGroupConfig(vTapGroupConfig)
	JsonResponse(c, data, err)
}

func deleteVTapGroupConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	data, err := service.DeleteVTapGroupConfig(lcuuid)
	JsonResponse(c, data, err)
}

func updateVTapGroupConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	vTapGroupConfig := &model.VTapGroupConfiguration{}
	c.ShouldBindBodyWith(&vTapGroupConfig, binding.JSON)
	data, err := service.UpdateVTapGroupConfig(lcuuid, vTapGroupConfig)
	JsonResponse(c, data, err)
}

func getVTapGroupConfigs(c *gin.Context) {
	data, err := service.GetVTapGroupConfigs()
	JsonResponse(c, data, err)
}

func getVTapGroupDetailedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	data, err := service.GetVTapGroupDetailedConfig(lcuuid)
	JsonResponse(c, data, err)
}

func getVTapGroupAdvancedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	data, err := service.GetVTapGroupAdvancedConfig(lcuuid)
	JsonResponse(c, data, err)
}

func updateVTapGroupAdvancedConfig(c *gin.Context) {
	lcuuid := c.Param("lcuuid")
	vTapGroupConfig := &model.VTapGroupConfiguration{}
	c.ShouldBindBodyWith(&vTapGroupConfig, binding.YAML)
	data, err := service.UpdateVTapGroupAdvancedConfig(lcuuid, vTapGroupConfig)
	JsonResponse(c, data, err)
}
