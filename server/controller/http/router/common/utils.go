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

package common

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlcommon "github.com/deepflowio/deepflow/server/controller/db/mysql/common"
)

var ClusterIDRegex = regexp.MustCompile("^[0-9a-zA-Z][-0-9a-zA-Z]{0,31}$")

func GetContextOrgDB(ctx *gin.Context) (*mysql.DB, error) {
	orgID, exist := ctx.Get(common.HEADER_KEY_X_ORG_ID)
	if !exist {
		return nil, errors.New(fmt.Sprintf("invalid org id (%v)", orgID))
	}

	db, err := mysql.GetDB(orgID.(int))
	if err != nil {
		return nil, err
	}
	return db, nil
}

func GetContextOrgID(ctx *gin.Context) (int, error) {
	orgID := mysqlcommon.DEFAULT_ORG_ID
	orgIDString := ctx.Request.Header.Get(common.HEADER_KEY_X_ORG_ID)
	if orgIDString != "" {
		oID, err := strconv.Atoi(orgIDString)
		if err != nil {
			return 0, err
		}
		orgID = oID
	}
	return orgID, nil
}

func CheckClusterID(clusterID string) bool {
	return ClusterIDRegex.MatchString(clusterID)
}
