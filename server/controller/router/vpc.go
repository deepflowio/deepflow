package router

import (
	"github.com/gin-gonic/gin"

	"github.com/deepflowys/deepflow/server/controller/service"
)

func VPCRouter(e *gin.Engine) {
	e.GET("/v2/vpcs/", getVPCs)
}

func getVPCs(c *gin.Context) {
	args := make(map[string]interface{})
	if value, ok := c.GetQuery("name"); ok {
		args["name"] = value
	}
	data, err := service.GetVPCs(args)
	JsonResponse(c, data, err)
}
