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

package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	_ "net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/spf13/cobra"
	_ "github.com/vishvananda/netlink"
)

// Filter query string parameters
type Filter map[string]interface{}

type HTTPConf struct {
	Timeout time.Duration
}

type HTTPOption func(*HTTPConf)

func WithTimeout(t time.Duration) HTTPOption {
	return func(h *HTTPConf) {
		h.Timeout = t
	}
}

// 功能：调用其他模块API并获取返回结果
func CURLPerform(method string, url string, body map[string]interface{}, strBody string, opts ...HTTPOption) (*simplejson.Json, error) {
	cfg := &HTTPConf{}
	for _, opt := range opts {
		opt(cfg)
	}

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

	return parseResponse(req, cfg)
}

func parseResponse(req *http.Request, cfg *HTTPConf) (*simplejson.Json, error) {
	errResponse, _ := simplejson.NewJson([]byte("{}"))
	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: cfg.Timeout}
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

func CURLPostFormData(url, contentType string, body *bytes.Buffer, opts ...HTTPOption) (*simplejson.Json, error) {
	cfg := &HTTPConf{}
	for _, opt := range opts {
		opt(cfg)
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Type", "1")
	req.Close = true

	return parseResponse(req, cfg)
}

func CURLResponseRawJson(method string, url string, opts ...HTTPOption) (*simplejson.Json, error) {
	cfg := &HTTPConf{}
	for _, opt := range opts {
		opt(cfg)
	}
	errResponse, _ := simplejson.NewJson([]byte("{}"))

	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: cfg.Timeout}

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

type Server struct {
	IP      string
	Port    uint32
	RpcPort uint32
	SvcPort uint32
}

func GetServerInfo(cmd *cobra.Command) *Server {
	ip, _ := cmd.Flags().GetString("ip")
	port, _ := cmd.Flags().GetUint32("api-port")
	rpcPort, _ := cmd.Flags().GetUint32("rpc-port")
	svcPort, _ := cmd.Flags().GetUint32("svc-port")
	return &Server{ip, port, rpcPort, svcPort}
}

func GetTimeout(cmd *cobra.Command) time.Duration {
	t, _ := cmd.Flags().GetDuration("timeout")
	return t
}

func PrettyPrint(data interface{}) {
	val, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Println(string(val))
}

func JsonFormat(jsonByte []byte) (string, error) {
	var str bytes.Buffer
	err := json.Indent(&str, jsonByte, "", "    ")
	if err != nil {
		return "", err
	}
	return str.String(), nil
}

// GetByFilter 通过 Get 方法获取数据，自动拼接 url param 参数
func GetByFilter(url string, body, filters map[string]interface{}, opts ...HTTPOption) (*simplejson.Json, error) {
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
	return CURLPerform("GET", url, body, "", opts...)
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

func ConvertControllerAddrToPodIP(controllerIP string, controllerPort uint32) (string, error) {
	url := fmt.Sprintf("http://%s:%d/v1/controllers/", controllerIP, controllerPort)
	resp, err := CURLResponseRawJson("GET", url)
	if err != nil {
		return "", err
	}
	var podIP string
	for c := range resp.Get("DATA").MustArray() {
		controller := resp.Get("DATA").GetIndex(c)
		pIP := controller.Get("POD_IP").MustString()
		if controllerIP == pIP || controller.Get("IP").MustString() == controllerIP {
			podIP = pIP
			break
		}
	}
	if podIP == "" {
		return "", errors.New(fmt.Sprintf("request (%s) get pod ip failed", url))
	}
	return podIP, nil
}

func GetURLInfo(cmd *cobra.Command, urlPath string, opts ...HTTPOption) {

	server := GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d", server.IP, server.Port) + urlPath

	response, err := CURLPerform("GET", url, nil, "", opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	responseByte, err := response.MarshalJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	var str bytes.Buffer
	err = json.Indent(&str, responseByte, "", "    ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	fmt.Println(str.String())
}
