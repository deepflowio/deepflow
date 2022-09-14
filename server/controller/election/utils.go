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

package election

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

// 功能：判断当前控制器是否为masterController
func IsMasterController() (bool, error) {
	// 获取本机hostname
	hostName := os.Getenv(common.POD_NAME_KEY)
	if len(hostName) == 0 {
		log.Error("hostname is null")
		return false, errors.New("hostname is null")
	}

	if _, enabled := os.LookupEnv("FEATURE_FLAG_ELECTION"); enabled {
		// get leader
		leaderID := GetLeader()
		// node_name/node_ip/pod_name/pod_ip
		leaderInfo := strings.Split(leaderID, "/")
		if len(leaderInfo) != ID_ITEM_NUM || leaderInfo[2] == "" {
			return false, errors.New(fmt.Sprintf("id (%s) is not expected", leaderID))
		}
		return hostName == leaderInfo[2], nil
	}

	// get node name
	nodeName := os.Getenv(common.NODE_NAME_KEY)
	if len(nodeName) == 0 {
		log.Error("nodename is null")
		return false, errors.New("nodename is null")
	}

	// 通过sideCar API获取MasterControllerName
	url := fmt.Sprintf("http://%s:%d", common.LOCALHOST, common.MASTER_CONTROLLER_CHECK_PORT)
	response, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		return false, err
	}
	masterControllerName := response.Get("name").MustString()

	// 比较是否相同返回结果
	if hostName != masterControllerName && nodeName != masterControllerName {
		return false, nil
	}
	return true, nil
}

func IsMasterControllerAndReturnName() (bool, string, error) {
	// get self hostname
	hostName := os.Getenv(common.POD_NAME_KEY)
	if len(hostName) == 0 {
		log.Error("hostname is null")
		return false, "", errors.New("hostname is null")
	}

	if _, enabled := os.LookupEnv("FEATURE_FLAG_ELECTION"); enabled {
		// get leader
		leaderID := GetLeader()
		// node_name/node_ip/pod_name/pod_ip
		leaderInfo := strings.Split(leaderID, "/")
		if len(leaderInfo) != ID_ITEM_NUM || leaderInfo[2] == "" {
			return false, "", errors.New(fmt.Sprintf("id (%s) is not expected", leaderID))
		}
		if hostName != leaderInfo[2] {
			return false, leaderInfo[2], nil
		}
		return true, hostName, nil
	}

	// 通过sideCar API获取MasterControllerName
	url := fmt.Sprintf("http://%s:%d", common.LOCALHOST, common.MASTER_CONTROLLER_CHECK_PORT)
	response, err := common.CURLPerform("GET", url, nil)
	if err != nil {
		return false, "", err
	}
	masterControllerName := response.Get("name").MustString()

	var masterController mysql.Controller
	if ret := mysql.Db.Where(
		"node_name = ? OR name = ?", masterControllerName, masterControllerName,
	).First(&masterController); ret.Error != nil {
		return false, "", err
	}

	// 比较是否相同返回结果
	if hostName != masterController.Name {
		return false, masterController.Name, nil
	}
	return true, hostName, nil
}
