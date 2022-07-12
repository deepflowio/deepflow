/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
