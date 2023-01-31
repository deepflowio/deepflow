package logger

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func GinLogFormat(param gin.LogFormatterParams) string {
	return fmt.Sprintf("%s [GIN] %s %s %s %d %s %s\n",
		param.TimeStamp.Format("2006-01-02 15:04:05.000"),
		param.ClientIP,
		param.Method,
		param.Path,
		param.StatusCode,
		param.Latency,
		param.ErrorMessage,
	)
}
