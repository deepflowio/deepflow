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
	"fmt"
	"net/http"
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/gin-gonic/gin"
)

func GetORGID(header http.Header) (int, error) {
	orgID := header.Get(common.HEADER_KEY_X_ORG_ID)
	if len(orgID) == 0 {
		log.Warningf("fail to get %v from request header", common.HEADER_KEY_X_ORG_ID)
		return 1, nil // TODO return err
	}
	return strconv.Atoi(orgID)
}

func ORGIDMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		orgID, err := GetORGID(ctx.Request.Header)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid %s header", common.HEADER_KEY_X_ORG_ID)})
			ctx.Abort()
			return
		}

		ctx.Set(common.HEADER_KEY_X_ORG_ID, orgID)
		ctx.Next()
	}
}
