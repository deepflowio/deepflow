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

package election

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/common"
)

// 功能：判断当前控制器是否为masterController
func IsMasterController() (bool, error) {
	// in standalone mode, the local machine is the master node because of all in one deployment
	if common.IsStandaloneRunningMode() == true {
		return true, nil
	}
	// get self host_ip
	hostIP := os.Getenv(common.POD_IP_KEY)
	if len(hostIP) == 0 {
		log.Error("pod_ip is null")
		return false, errors.New("pod_ip is null")
	}

	// get leader
	leaderID := GetLeader()
	// node_name/node_ip/pod_name/pod_ip
	leaderInfo := strings.Split(leaderID, "/")
	if len(leaderInfo) != ID_ITEM_NUM || leaderInfo[3] == "" {
		return false, errors.New(fmt.Sprintf("id (%s) is not expected", leaderID))
	}
	return hostIP == leaderInfo[3], nil
}

func IsMasterControllerAndReturnIP() (bool, string, error) {
	// in standalone mode, the local machine is the master node because of all in one deployment
	if common.IsStandaloneRunningMode() == true {
		return true, common.GetPodIP(), nil
	}
	// get self host_ip
	hostIP := os.Getenv(common.POD_IP_KEY)
	if len(hostIP) == 0 {
		log.Error("pod_ip is null")
		return false, "", errors.New("pod_ip is null")
	}

	// get leader
	leaderID := GetLeader()
	// node_name/node_ip/pod_name/pod_ip
	leaderInfo := strings.Split(leaderID, "/")
	if len(leaderInfo) != ID_ITEM_NUM || leaderInfo[3] == "" {
		return false, "", errors.New(fmt.Sprintf("id (%s) is not expected", leaderID))
	}
	if hostIP != leaderInfo[3] {
		return false, leaderInfo[3], nil
	}
	return true, hostIP, nil
}
