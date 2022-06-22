package router

import (
	"server/controller/common"
	"server/controller/config"
	"server/controller/model"
	"server/controller/monitor"
	"server/controller/service"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

func AnalyzerRouter(e *gin.Engine, m *monitor.AnalyzerCheck, cfg *config.ControllerConfig) {
	e.GET("/v1/analyzers/:lcuuid/", getAnalyzer)
	e.GET("/v1/analyzers/", getAnalyzers)
	e.PATCH("/v1/analyzers/:lcuuid/", updateAnalyzer(m, cfg))
	e.DELETE("/v1/analyzers/:lcuuid/", deleteAnalyzer(m))
}

func getAnalyzer(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetAnalyzers(args)
	JsonResponse(c, data, err)
}

func getAnalyzers(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQueryArray("state"); ok {
		args["states"] = value
	}
	if value, ok := c.GetQuery("ip"); ok {
		args["ip"] = value
	}
	if value, ok := c.GetQuery("region"); ok {
		args["region"] = value
	}
	data, err := service.GetAnalyzers(args)
	JsonResponse(c, data, err)
}

func updateAnalyzer(m *monitor.AnalyzerCheck, cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var analyzerUpdate model.AnalyzerUpdate

		// 如果不是masterController，将请求转发至是masterController
		isMasterController, masterControllerName, _ := common.IsMasterController()
		if !isMasterController {
			forwardMasterController(c, masterControllerName)
			return
		}

		// 参数校验
		err = c.ShouldBindBodyWith(&analyzerUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")
		data, err := service.UpdateAnalyzer(lcuuid, patchMap, m, cfg)
		JsonResponse(c, data, err)
	})
}

func deleteAnalyzer(m *monitor.AnalyzerCheck) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		data, err := service.DeleteAnalyzer(lcuuid, m)
		JsonResponse(c, data, err)
	})
}
