package router

import (
	"github.com/gin-gonic/gin"

	"server/controller/monitor"
	"server/controller/service"
)

func LicenseRouter(e *gin.Engine, m *monitor.VTapLicenseAllocation) {
	e.GET("/v1/license-consumption/", getLicenseConsumption(m))
	e.GET("/v1/vtap-license-consumption/", getVTapLicenseConsumption(m))
}

func getLicenseConsumption(m *monitor.VTapLicenseAllocation) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetLicenseConsumption(m)
		JsonResponse(c, data, err)
		return
	})
}

func getVTapLicenseConsumption(m *monitor.VTapLicenseAllocation) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		data, err := service.GetVTapLicenseConsumption(m)
		JsonResponse(c, data, err)
		return
	})
}
