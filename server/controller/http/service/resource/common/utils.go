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

package common

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/common"
	servicecommon "github.com/deepflowio/deepflow/server/controller/http/service/common"
)

func GetUserInfoFromHTTPHeader(header http.Header) (userType, userID int, err error) {
	userTypes, _ := header[HEADER_KEY_X_USER_TYPE]
	if len(userTypes) == 0 {
		err = servicecommon.NewError(common.INVALID_PARAMETERS, fmt.Sprintf("No %s in request header", HEADER_KEY_X_USER_TYPE))
	} else {
		userType, err = strconv.Atoi(userTypes[0])
	}
	userIDs, _ := header[HEADER_KEY_X_USER_ID]
	if len(userIDs) == 0 {
		err = servicecommon.NewError(common.INVALID_PARAMETERS, fmt.Sprintf("No %s in request header", HEADER_KEY_X_USER_ID))
	} else {
		userID, err = strconv.Atoi(userIDs[0])
	}
	return
}
