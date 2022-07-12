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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

// 功能：调用其他模块API并获取返回结果
func CURLPerform(method string, url string, body map[string]interface{}, strBody string) (*simplejson.Json, error) {
	errResponse, _ := simplejson.NewJson([]byte("{}"))

	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: time.Second * 30}

	var err error
	var contentType string
	req := &http.Request{}
	if strBody != "" {
		reader := strings.NewReader(strBody)
		req, err = http.NewRequest(method, url, reader)
		contentType = "application/x-www-form-urlencoded"
	} else {
		bodyStr, _ := json.Marshal(&body)
		reader := bytes.NewReader(bodyStr)
		req, err = http.NewRequest(method, url, reader)
		contentType = "application/json"
	}

	if err != nil {
		return errResponse, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Type", "1")

	resp, err := client.Do(req)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", url, err))
	} else if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", url, resp))
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("read (%s) body failed, (%v)", url, err))
	}

	response, err := simplejson.NewJson(respBytes)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("parse (%s) body failed, (%v)", url, err))
	}

	optStatus := response.Get("OPT_STATUS").MustString()
	if optStatus != "" && optStatus != SUCCESS {
		description := response.Get("DESCRIPTION").MustString()
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%s)", url, description))
	}

	return response, nil
}

func GetDefaultRouteIP() string {
	defaultRouteIP := "127.0.0.1"
	routeList, _ := netlink.RouteList(nil, netlink.FAMILY_V4)
	for _, route := range routeList {
		// a nil Dst means that this is the default route.
		if route.Dst == nil {
			i, err := net.InterfaceByIndex(route.LinkIndex)
			if err != nil {
				continue
			}
			addresses, _ := i.Addrs()
			for _, address := range addresses {
				defaultRouteIP = strings.Split(address.String(), "/")[0]
				break
			}
		}
	}
	return defaultRouteIP
}

type Server struct {
	IP   string
	Port uint32
}

func GetServerInfo(cmd *cobra.Command) *Server {
	ip, _ := cmd.Flags().GetString("ip")
	port, _ := cmd.Flags().GetUint32("port")
	return &Server{ip, port}
}
