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

package mysql

import (
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func getVTapInfo(vtap *mysql.VTap) map[string]interface{} {
	if vtap == nil || vtap.ID == 0 {
		return map[string]interface{}{
			"VTAP_NAME":         nil,
			"VTAP_ID":           nil,
			"VTAP_LCUUID":       nil,
			"VTAP_TYPE":         nil,
			"VTAP_GROUP_LCUUID": nil,
			"VTAP_STATE":        nil,
		}
	}

	state := ctrlcommon.VTAP_STATE_DISABLE
	if vtap.Enable == 1 {
		state = vtap.State
	}

	return map[string]interface{}{
		"VTAP_NAME":         vtap.Name,
		"VTAP_ID":           vtap.ID,
		"VTAP_LCUUID":       vtap.Lcuuid,
		"VTAP_TYPE":         vtap.Type,
		"VTAP_GROUP_LCUUID": vtap.VtapGroupLcuuid,
		"VTAP_STATE":        state,
	}
}

type Number interface {
	int | string
}

func convertMapToSlice[k1 Number, k2 Number](maps map[k1]map[k2]struct{}) map[k1][]k2 {
	result := make(map[k1][]k2)
	for key, values := range maps {
		for value := range values {
			result[key] = append(result[key], value)
		}
	}
	return result
}
