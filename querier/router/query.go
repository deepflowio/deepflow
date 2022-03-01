package router

import (
	"github.com/gin-gonic/gin"
	"metaflow/querier/service"
)

func QueryRouter(e *gin.Engine) {
	e.GET("/v1/query/:db/", executeQuery())
}

func executeQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]string)
		json := make(map[string]interface{})
		c.BindJSON(&json)
		args["db"] = c.Param("db")
		args["sql"] = json["sql"].(string)
		args["ip"] = json["ip"].(string)
		data, err := service.Execute(args)
		JsonResponse(c, data, err)
	})
}
