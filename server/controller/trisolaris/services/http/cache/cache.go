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

package cache

import (
	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"github.com/metaflowys/metaflow/server/controller/trisolaris"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http"
	"github.com/metaflowys/metaflow/server/controller/trisolaris/server/http/common"
)

var log = logging.MustGetLogger("trisolaris/cache")

const (
	VTAP_CHANGED          = "vtap"
	ANALYZER_CHANGED      = "analyzer"
	PLATFORM_DATA_CHANGED = "platform_data"
	FLOW_ACL_CHANGED      = "flow_acl "
	GROUP_CHANGED         = "group"
	TAP_TYPE_CHANGED      = "tap_type"
	SERVICE_CHANGED       = "service"
)

func init() {
	http.Register(NewCacheService())
}

type CacheService struct{}

func NewCacheService() *CacheService {
	return &CacheService{}
}

func PutCache(c *gin.Context) {
	log.Debug(c.GetQueryArray("type"))
	if changedTypes, ok := c.GetQueryArray("type"); ok {
		for _, changedType := range changedTypes {
			switch changedType {
			case PLATFORM_DATA_CHANGED:
				trisolaris.PutPlatformData()
			case ANALYZER_CHANGED:
				trisolaris.PutNodeInfo()
			case VTAP_CHANGED:
				trisolaris.PutVTapCache()
			case TAP_TYPE_CHANGED:
				trisolaris.PutTapType()
			}
		}
	}
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*CacheService) Register(mux *gin.Engine) {
	mux.PUT("v1/caches/", PutCache)
}
