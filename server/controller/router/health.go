package router

import (
	"github.com/gin-gonic/gin"
)

func HealthRouter(e *gin.Engine) {
	e.GET("/v1/health/", func(c *gin.Context) {
		JsonResponse(c, make(map[string]string), nil)
	})
}
