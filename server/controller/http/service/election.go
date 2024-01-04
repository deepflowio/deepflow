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

package service

import (
	"fmt"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/election"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
)

func GetLeaderInfo() (resp map[string]string, err error) {
	leaderID := election.GetLeader()
	// node_name/node_ip/pod_name/pod_ip
	leaderInfo := strings.Split(leaderID, "/")
	if len(leaderInfo) != election.ID_ITEM_NUM || leaderInfo[0] == "" {
		return map[string]string{}, NewError(httpcommon.SERVER_ERROR, fmt.Sprintf("id (%s) is not expected", leaderID))
	}
	return map[string]string{
		"NODE_NAME": leaderInfo[0],
		"NODE_IP":   leaderInfo[1],
		"POD_NAME":  leaderInfo[2],
		"POD_IP":    leaderInfo[3],
	}, nil
}
