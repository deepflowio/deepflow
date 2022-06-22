package http

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("trisolaris/http")

func RequestLoggerMiddleware(c *gin.Context) {
	start := time.Now()
	c.Next()
	end := time.Now()
	latency := end.Sub(start)
	path := c.Request.URL.Path
	clientIP := c.ClientIP()
	method := c.Request.Method
	statusCode := c.Writer.Status()
	log.Infof("| %3d | %10v | %12s | %s  %s |",
		statusCode,
		latency,
		clientIP,
		method, path,
	)
}
