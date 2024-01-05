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

package router

import (
	"net/http"

	"github.com/deepflowio/deepflow/server/libs/datastructure"
	"github.com/gin-gonic/gin"
)

// rate limit middleware
func Limiter(limiter *datastructure.LeakyBucket) gin.HandlerFunc {
	return func(c *gin.Context) {
		// QPS Limit Check
		// Both SetRate and Acquire are expanded by 1000 times, making it suitable for small QPS scenarios.
		if !limiter.Acquire(1000) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}
