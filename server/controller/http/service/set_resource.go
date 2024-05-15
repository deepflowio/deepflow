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

package service

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/common"
)

func SetReource(method string, fpermit common.FPermit, body map[string]interface{}, userInfo *UserInfo) error {
	if !fpermit.Enabled {
		return nil
	}

	_, err := common.CURLPerform(
		method,
		fmt.Sprintf("http://%s:%d/v1/org/%d/resource", fpermit.Host, fpermit.Port, userInfo.ORGID),
		body,
		common.WithHeader(common.HEADER_X_APP_KEY, common.DEFAULT_APP_KEY),
		common.WithHeader(common.HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", userInfo.Type)),
		common.WithHeader(common.HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", userInfo.ID)),
	)
	if err != nil {
		return err
	}
	return nil
}
