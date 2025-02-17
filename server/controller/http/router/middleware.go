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

package router

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/common"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/gin-gonic/gin"
)

// AdminPermissionverificationMiddleware is a Gin middleware that checks if the user is a super admin or admin.
func AdminPermissionVerificationMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userType, _ := ctx.Get(common.HEADER_KEY_X_USER_TYPE)
		if !(userType == common.USER_TYPE_SUPER_ADMIN || userType == common.USER_TYPE_ADMIN) {
			response.JSON(ctx, response.SetOptStatus(httpcommon.NO_PERMISSIONS), response.SetError(fmt.Errorf("only super admin and admin can operate")))
			ctx.Abort()
		}
		ctx.Next()
	}
}
