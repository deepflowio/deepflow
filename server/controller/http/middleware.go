/**
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

package http

import (
	"fmt"
	nhttp "net/http"
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/common"
	mcommon "github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/gin-gonic/gin"
)

func HandleOrgIDMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		orgID := mcommon.DEFAULT_ORG_ID
		orgIDString := ctx.Request.Header.Get(common.HEADER_KEY_X_ORG_ID)
		if len(orgIDString) != 0 {
			_, err := strconv.Atoi(orgIDString)
			if err != nil {
				ctx.JSON(nhttp.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid header (%s) value (%s)", common.HEADER_KEY_X_ORG_ID, orgIDString)})
				ctx.Abort()
				return
			}
		} else {
			ctx.Request.Header.Set(common.HEADER_KEY_X_ORG_ID, strconv.Itoa(orgID))
		}
		ctx.Next()
	}
}
