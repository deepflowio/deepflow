package router

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"server/controller/common"
	"server/controller/config"
	"server/controller/model"
	"server/controller/monitor"
	"server/controller/service"
)

func ControllerRouter(e *gin.Engine, m *monitor.ControllerCheck, cfg *config.Config) {
	e.GET("/v1/controllers/:lcuuid/", getController)
	e.GET("/v1/controllers/", getControllers)
	e.PATCH("/v1/controllers/:lcuuid/", updateController(m, cfg))
	e.DELETE("/v1/controllers/:lcuuid/", deleteController(m))
}

func getController(c *gin.Context) {
	args := make(map[string]string)
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetControllers(args)
	JsonResponse(c, data, err)
}

func getControllers(c *gin.Context) {
	args := make(map[string]string)
	if value, ok := c.GetQuery("ip"); ok {
		args["ip"] = value
	}
	if value, ok := c.GetQuery("controller"); ok {
		args["name"] = value
	}
	if value, ok := c.GetQuery("analyzer"); ok {
		args["analyzer_name"] = value
	}
	if value, ok := c.GetQuery("vtap"); ok {
		args["vtap_name"] = value
	}
	if value, ok := c.GetQuery("region"); ok {
		args["region"] = value
	}
	data, err := service.GetControllers(args)
	JsonResponse(c, data, err)
}

func updateController(m *monitor.ControllerCheck, cfg *config.Config) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var controllerUpdate model.ControllerUpdate

		// 如果不是masterController，将请求转发至是masterController
		isMasterController, masterControllerName, _ := common.IsMasterController()
		if !isMasterController {
			forwardMasterController(c, masterControllerName)
			return
		}

		// 参数校验
		err = c.ShouldBindBodyWith(&controllerUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")
		data, err := service.UpdateController(lcuuid, patchMap, m, cfg)
		JsonResponse(c, data, err)
	})
}

func deleteController(m *monitor.ControllerCheck) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		lcuuid := c.Param("lcuuid")
		data, err := service.DeleteController(lcuuid, m)
		JsonResponse(c, data, err)
		return
	})
}
