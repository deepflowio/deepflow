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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
)

var (
	SUCCESS = "SUCCESS"

	ErrorFail    = errors.New("FAIL")
	ErrorPending = errors.New("PENDING")

	errResponse, _ = simplejson.NewJson([]byte("{}"))
)

// 功能：获取用于API调用的IP地址
func GetCURLIP(ip string) string {
	// IPV6地址在API调用时需要增加[]
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return "[" + ip + "]"
	}
	return ip
}

type HeaderOption func(req *http.Request)

func WithHeader(key, value string) HeaderOption {
	return func(req *http.Request) {
		req.Header.Set(key, value)
	}
}

func WithORGHeader(value string) HeaderOption {
	return func(req *http.Request) {
		req.Header.Set(HEADER_KEY_X_ORG_ID, value)
	}
}

func fillHeader(req *http.Request) {
	if req.Header.Get(HEADER_KEY_X_USER_ID) == "" {
		req.Header.Set(HEADER_KEY_X_USER_ID, fmt.Sprintf("%d", USER_ID_SUPER_ADMIN))
	}
	if req.Header.Get(HEADER_KEY_X_USER_TYPE) == "" {
		req.Header.Set(HEADER_KEY_X_USER_TYPE, fmt.Sprintf("%d", USER_TYPE_SUPER_ADMIN))
	}
	if req.Header.Get(HEADER_KEY_ACCEPT) == "" {
		req.Header.Set(HEADER_KEY_ACCEPT, ACCEPT_JSON)
	}
	if req.Header.Get(HEADER_KEY_X_APP_KEY) == "" {
		req.Header.Set(HEADER_KEY_X_APP_KEY, DEFAULT_APP_KEY)
	}
}

// CURLPerform 调用 deepflow 其他服务 API 并获取返回结果，Content-Type 为 application/json
func CURLPerform(method string, url string, body map[string]interface{}, options ...HeaderOption) (*simplejson.Json, error) {
	log.Debugf("curl perform: %s %s %+v", method, url, body)
	bodyStr, _ := json.Marshal(&body)
	req, err := http.NewRequest(method, url, bytes.NewReader(bodyStr))
	if err != nil {
		log.Error(err)
		return errResponse, err
	}
	req.Header.Set(HEADER_KEY_CONTENT_TYPE, CONTENT_TYPE_JSON)
	return doRequest(req, url, options...)
}

// CURLPerform2 调用 deepflow 其他服务, 如 querier API 并获取返回结果，Content-Type 为 application/x-www-form-urlencoded
func CURLPerform2(method string, url string, postData map[string]string, options ...HeaderOption) (*simplejson.Json, error) {
	log.Debugf("curl perform: %s %s %+v", method, url, postData)
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	for k, v := range postData {
		w.WriteField(k, v)
	}
	w.Close()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		log.Error(err)
		return errResponse, err
	}
	req.Header.Set(HEADER_KEY_CONTENT_TYPE, w.FormDataContentType())
	return doRequest(req, url, options...)
}

func doRequest(req *http.Request, url string, options ...HeaderOption) (*simplejson.Json, error) {
	for _, option := range options {
		option(req)
	}
	fillHeader(req)

	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: time.Second * 30}
	resp, err := client.Do(req)
	if err != nil {
		return errResponse, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("curl: %s failed, response detail: %+v", url, resp)
		if respBytes, err := io.ReadAll(resp.Body); err == nil {
			if response, err := simplejson.NewJson(respBytes); err == nil {
				description := response.Get("DESCRIPTION").MustString()
				if description != "" {
					errMsg += fmt.Sprintf(", description: %s", description)
				}
			}
		}
		log.Error(errMsg)
		return errResponse, errors.New(errMsg)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("read (%s) body failed, (%v)", url, err)
		return errResponse, err
	}

	response, err := simplejson.NewJson(respBytes)
	if err != nil {
		log.Errorf("parse (%s) body failed, (%v)", url, err)
		return errResponse, err
	}

	optStatus := response.Get("OPT_STATUS").MustString()
	if optStatus != "" && optStatus != SUCCESS {
		description := response.Get("DESCRIPTION").MustString()
		log.Errorf("curl: %s failed, (%s)", url, description)
		e := ErrorFail
		// PENDING used for api /v1/rpmod/
		if optStatus == "PENDING" {
			e = ErrorPending
		}
		return errResponse, fmt.Errorf("%w, %s", e, description)
	}

	return response, nil
}

// TODO optimize
// CURLForm 调用 deepflow 其他服务 API 并获取返回结果，Content-Type 为 application/x-www-form-urlencoded
func CURLForm(method string, url string, values url.Values, options ...HeaderOption) (*simplejson.Json, error) {
	log.Debugf("curl form: %s %s %+v", method, url, values)
	req, err := http.NewRequest(method, url, strings.NewReader(values.Encode()))
	if err != nil {
		log.Error(err)
		return errResponse, err
	}
	req.Header.Set(HEADER_KEY_CONTENT_TYPE, CONTENT_TYPE_FORM)
	return doRequest(req, url, options...)
}
