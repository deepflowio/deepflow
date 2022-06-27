package router

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	// "github.com/k0kubun/pp"
	//logging "github.com/op/go-logging"
	"github.com/metaflowys/metaflow/server/querier/service"
)

func QueryRouter(e *gin.Engine) {
	e.POST("/v1/query/", executeQuery())
}

func executeQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := make(map[string]string)
		args["debug"] = c.Query("debug")
		args["query_uuid"] = c.Query("query_uuid")
		if args["query_uuid"] == "" {
			query_uuid := uuid.New()
			args["query_uuid"] = query_uuid.String()
		}
		args["db"] = c.PostForm("db")
		args["sql"] = c.PostForm("sql")
		args["datasource"] = c.PostForm("datasource")
		if args["sql"] == "" && args["db"] == "" {
			json := make(map[string]interface{})
			c.BindJSON(&json)
			args["db"], _ = json["db"].(string)
			args["sql"], _ = json["sql"].(string)
		}
		result, debug, err := service.Execute(args)
		if err == nil && args["debug"] != "true" {
			debug = nil
		}
		JsonResponse(c, result, debug, err)
	})
}
