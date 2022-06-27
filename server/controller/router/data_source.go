package router

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/config"
	"github.com/metaflowys/metaflow/server/controller/model"
	"github.com/metaflowys/metaflow/server/controller/service"
)

func DataSourceRouter(e *gin.Engine, cfg *config.ControllerConfig) {
	e.GET("/v1/data-sources/:lcuuid/", getDataSource)
	e.GET("/v1/data-sources/", getDataSources)
	e.POST("/v1/data-sources/", createDataSource(cfg))
	e.PATCH("/v1/data-sources/:lcuuid/", updateDataSource(cfg))
	e.DELETE("/v1/data-sources/:lcuuid/", deleteDataSource(cfg))
}

func getDataSource(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetDataSources(args)
	JsonResponse(c, data, err)
}

func getDataSources(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("type"); ok {
		args["type"] = value
	}
	if value, ok := c.GetQuery("name"); ok {
		args["name"] = value
	}
	data, err := service.GetDataSources(args)
	JsonResponse(c, data, err)
}

func createDataSource(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var dataSourceCreate model.DataSourceCreate

		// 参数校验
		err = c.ShouldBindBodyWith(&dataSourceCreate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}

		data, err := service.CreateDataSource(dataSourceCreate, cfg)
		JsonResponse(c, data, err)
	})
}

func updateDataSource(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error
		var dataSourceUpdate model.DataSourceUpdate

		// 参数校验
		err = c.ShouldBindBodyWith(&dataSourceUpdate, binding.JSON)
		if err != nil {
			BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
			return
		}

		lcuuid := c.Param("lcuuid")
		data, err := service.UpdateDataSource(lcuuid, dataSourceUpdate, cfg)
		JsonResponse(c, data, err)
	})
}

func deleteDataSource(cfg *config.ControllerConfig) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		var err error

		lcuuid := c.Param("lcuuid")
		data, err := service.DeleteDataSource(lcuuid, cfg)
		JsonResponse(c, data, err)
	})
}
