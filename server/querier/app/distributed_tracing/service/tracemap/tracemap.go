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
package tracemap

import (
	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/querier/app/distributed_tracing/model"
	"github.com/deepflowio/deepflow/server/querier/config"
)

func TraceMap(args model.TraceMap, cfg *config.QuerierConfig, c *gin.Context, done chan bool, generator *TraceMapGenerator) {
	done <- true
	return
}

func FlowMap(args model.FlowMap, cfg *config.QuerierConfig, c *gin.Context, generator *TraceMapGenerator) {
	return
}
