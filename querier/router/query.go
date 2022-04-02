package router

import (
	"github.com/gin-gonic/gin"
	//"github.com/k0kubun/pp"

	"metaflow/querier/service"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())
}

func executeQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]string)
		args["debug"] = c.Query("debug")
		args["db"] = c.PostForm("db")
		args["sql"] = c.PostForm("sql")
		result, debug, err := service.Execute(args)
		if args["debug"] != "true" {
			debug = nil
		}
		JsonResponse(c, result, debug, err)
	})
}
