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
	"net"

	simplejson "github.com/bitly/go-simplejson"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func GetSelfController() (*mysql.Controller, error) {
	var controller *mysql.Controller
	err := mysql.Db.Where("ip = ?", GetNodeIP()).Find(&controller).Error
	return controller, err
}

func GetMasterControllerHostPort() (masterIP string, httpPort, grpcPort int, err error) {
	var host string
	curController, err := GetSelfController()
	if err != nil {
		return
	}
	var resp *simplejson.Json
	if curController.NodeType == CONTROLLER_NODE_TYPE_MASTER {
		host = LOCALHOST
		httpPort = GConfig.HTTPPort
		grpcPort = GConfig.GRPCPort
		url := fmt.Sprintf("http://%s/v1/election-leader/", net.JoinHostPort(host, fmt.Sprintf("%d", httpPort)))
		resp, err = CURLPerform("GET", url, nil)
		if err != nil {
			return
		}
	} else {
		var controllers []*mysql.Controller
		err = mysql.Db.Where("node_type = ? AND state = ?", CONTROLLER_NODE_TYPE_MASTER, CONTROLLER_STATE_NORMAL).Find(&controllers).Error
		if err != nil {
			return
		}
		httpPort = GConfig.HTTPNodePort
		grpcPort = GConfig.GRPCNodePort
		var respGetted bool
		for _, c := range controllers {
			host = c.IP
			err = IsTCPActive(host, httpPort)
			if err != nil {
				log.Error(err.Error())
				continue
			}

			url := fmt.Sprintf("http://%s/v1/election-leader/", net.JoinHostPort(host, fmt.Sprintf("%d", httpPort)))
			resp, err = CURLPerform("GET", url, nil)
			if err == nil {
				respGetted = true
				break
			}
		}
		if !respGetted {
			err = errors.New(fmt.Sprintf("request all controllers in master reigon failed: %s", err.Error()))
			return
		}
	}
	if curController.NodeType == CONTROLLER_NODE_TYPE_MASTER {
		masterIP = resp.Get("DATA").Get("POD_IP").MustString()
	} else {
		masterIP = resp.Get("DATA").Get("NODE_IP").MustString()
	}
	return
}

func CheckSelfAndGetMasterControllerHostPort() (ok bool, masterCtrlIP string, httpPort, grpcPort int, err error) {
	curCtrlIP := GetPodIP()
	masterCtrlIP, httpPort, grpcPort, err = GetMasterControllerHostPort()
	return curCtrlIP == masterCtrlIP, masterCtrlIP, httpPort, grpcPort, err
}
