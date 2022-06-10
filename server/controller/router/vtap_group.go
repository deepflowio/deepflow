package router

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"server/controller/common"
	"server/controller/config"
	"server/controller/model"
	"server/controller/service"
)

func VtapGroupRouter(e *gin.Engine, cfg *config.Config) {
	e.GET("/v1/vtap-groups/:lcuuid/", getVtapGroup)
	e.GET("/v1/vtap-groups/", getVtapGroups)
	e.POST("/v1/vtap-groups/", createVtapGroup(cfg))
	e.PATCH("/v1/vtap-groups/:lcuuid/", updateVtapGroup(cfg))
	e.DELETE("/v1/vtap-groups/:lcuuid/", deleteVtapGroup)
}

func getVtapGroup(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetVtapGroups(args)
	JsonResponse(c, data, err)
}

func getVtapGroups(c *gin.Context) {
	args := make(map[string]interface{})
	data, err := service.GetVtapGroups(args)
	JsonResponse(c, data, err)
}

func createVtapGroup(cfg *config.Config) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var vtapGroupCreate model.VtapGroupCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapGroupCreate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}

		data, err := service.CreateVtapGroup(vtapGroupCreate, cfg)
		JsonResponse(c, data, err)
	})
}

func updateVtapGroup(cfg *config.Config) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var vtapGroupUpdate model.VtapGroupUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&vtapGroupUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
			return
		}

		// 接收参数
		// 避免struct会有默认值，这里转为map作为函数入参
		patchMap := map[string]interface{}{}
		c.ShouldBindBodyWith(&patchMap, binding.JSON)

		lcuuid := c.Param("lcuuid")
		data, err := service.UpdateVtapGroup(lcuuid, patchMap, cfg)
		JsonResponse(c, data, err)
	})
}

func deleteVtapGroup(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := service.DeleteVtapGroup(lcuuid)
	JsonResponse(c, data, err)
}
