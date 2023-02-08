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
	"os"
	"regexp"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

// Filter query string parameters
type Filter map[string]interface{}

// 功能：调用其他模块API并获取返回结果
func CURLPerform(method string, url string, body map[string]interface{}, strBody string) (*simplejson.Json, error) {
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
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Type", "1")

	return parseResponse(req)
}

func parseResponse(req *http.Request) (*simplejson.Json, error) {
	errResponse, _ := simplejson.NewJson([]byte("{}"))
	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: time.Second * 30}
	resp, err := client.Do(req)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", req.URL, err))
	}

	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("read (%s) body failed, (%v)", req.URL, err))
	}
	if resp.StatusCode != http.StatusOK {
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", req.URL, string(respBytes)))
	}

	response, err := simplejson.NewJson(respBytes)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("parse (%s) body failed, (%v)", req.URL, err))
	}

	optStatus := response.Get("OPT_STATUS").MustString()
	if optStatus != "" && optStatus != SUCCESS {
		description := response.Get("DESCRIPTION").MustString()
		return response, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", req.URL, description))
	}
	return response, nil
}

func CURLPostFormData(url, contentType string, body *bytes.Buffer) (*simplejson.Json, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Type", "1")
	req.Close = true

	return parseResponse(req)
}

func CURLResponseRawJson(method string, url string) (*simplejson.Json, error) {
	errResponse, _ := simplejson.NewJson([]byte("{}"))

	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: time.Second * 30}

	var err error
	req := &http.Request{}
	req, err = http.NewRequest(method, url, nil)

	if err != nil {
		return errResponse, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Type", "1")

	resp, err := client.Do(req)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed, (%v)", url, err))
	}

	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errResponse, errors.New(fmt.Sprintf("read (%s) body failed, (%v)", url, err))
	}

	response, err := simplejson.NewJson(respBytes)
	if resp.StatusCode != http.StatusOK {
		var description string
		_, ok := response.CheckGet("DESCRIPTION")
		if ok {
			description = response.Get("DESCRIPTION").MustString()
		}
		return response, errors.New(fmt.Sprintf("curl (%s) failed, (%v %v)", url, resp.StatusCode, description))
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
	IP      string
	Port    uint32
	RpcPort uint32
}

func GetServerInfo(cmd *cobra.Command) *Server {
	ip, _ := cmd.Flags().GetString("ip")
	port, _ := cmd.Flags().GetUint32("api-port")
	rpcPort, _ := cmd.Flags().GetUint32("rpc-port")
	return &Server{ip, port, rpcPort}
}

func PrettyPrint(data interface{}) {
	val, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Println(string(val))
}

func JsonFormat(jsonStr string) (string, error) {
	var str bytes.Buffer
	err := json.Indent(&str, []byte(jsonStr), "", "    ")
	if err != nil {
		return "", err
	}
	return str.String(), nil
}

// GetByFilter 通过 Get 方法获取数据，自动拼接 url param 参数
func GetByFilter(url string, body, filters map[string]interface{}) (*simplejson.Json, error) {
	if !strings.HasSuffix(url, "/") {
		url = url + "/"
	}
	if !strings.HasSuffix(url, "?") {
		url = url + "?"
	}

	i, count := 0, len(filters)
	for k, v := range filters {
		url += fmt.Sprintf("%v=%v", k, v)
		if i < count-1 {
			url += "&"
		}
		i++
	}
	return CURLPerform("GET", url, body, "")
}

var chinesePunctuationRegex = regexp.MustCompile("[(\u4e00-\u9fa5)(\u3002|\uff1f|\uff01|\uff0c|\u3001|\uff1b|\uff1a|\u201c|\u201d|\u2018|\u2019|\uff08|\uff09|\u300a|\u300b|\u3010|\u3011|\u007e)]+")

func IsChineseChar(str string) bool {
	for _, r := range str {
		if chinesePunctuationRegex.MatchString(string(r)) {
			return true
		}
	}
	return false
}
