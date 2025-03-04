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

package cache

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/server/http/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("trisolaris.cache")

func init() {
	http.Register(NewCacheService())
}

type CacheService struct{}

func NewCacheService() *CacheService {
	return &CacheService{}
}

func PutCache(c *gin.Context) {
	log.Debug(c.GetQueryArray("type"))
	var err error
	orgID := 0
	orgIDStr, ok := c.GetQuery("org_id")
	if ok {
		orgID, err = strconv.Atoi(orgIDStr)
		if err != nil {
			common.Response(c, nil, common.NewReponse("FAILED", "", nil, err.Error()))
			return
		}
	} else {
		if headerOrgID, ok := c.Get(HEADER_KEY_X_ORG_ID); ok {
			orgID = headerOrgID.(int)
		}
	}
	if utils.CheckOrgID(orgID) == false {
		errMessage := fmt.Sprintf("check orgID(%d) failed", orgID)
		common.Response(c, nil, common.NewReponse("FAILED", "", nil, errMessage))
		return
	}
	if changedTypes, ok := c.GetQueryArray("type"); ok {
		for _, changedType := range changedTypes {
			switch DataChanged(changedType) {
			case DATA_CHANGED_PLATFORM_DATA:
				trisolaris.PutPlatformData(orgID)
			case DATA_CHANGED_ANALYZER:
				trisolaris.PutNodeInfo(orgID)
			case DATA_CHANGED_VTAP:
				trisolaris.PutVTapCache(orgID)
			case DATA_CHANGED_TAP_TYPE:
				trisolaris.PutTapType(orgID)
			case DATA_CHANGED_FLOW_ACL:
				trisolaris.PutFlowACL(orgID)
			case DATA_CHANGED_GROUP, DATA_CHANGED_SERVICE:
				trisolaris.PutGroup(orgID)
			case DATA_CHANGED_IMAGE:
				trisolaris.DeleteImageCache(c.DefaultQuery("image_name", ""))
			}
		}
	}
	common.Response(c, nil, common.NewReponse("SUCCESS", "", nil, ""))
}

func (*CacheService) Register(mux *gin.Engine) {
	mux.PUT("v1/caches/", PutCache)
}
