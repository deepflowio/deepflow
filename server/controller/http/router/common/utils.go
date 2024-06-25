/**
 * Copyright (c) 2023 Yunshan Networks
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

package common

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
)

func UserTypePermissionVerify(c *gin.Context) error {
	var err error
	userType := ccommon.DEFAULT_USER_TYPE
	userTypeString := c.Request.Header.Get(ccommon.HEADER_KEY_X_USER_TYPE)
	if len(userTypeString) != 0 {
		userType, err = strconv.Atoi(userTypeString)
		if err != nil {
			return fmt.Errorf("invalid user type (%s)", userTypeString)
		}
	}
	if userType != ccommon.USER_TYPE_SUPER_ADMIN && userType != ccommon.USER_TYPE_ADMIN {
		return fmt.Errorf("user type (%d) permission denied, can not operate", userType)
	}
	return nil
}
