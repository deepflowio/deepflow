/*
 * Copyright (c) 2024 Yunshan Networks
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
