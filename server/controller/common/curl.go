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
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"

	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
)

// 功能：获取用于API调用的IP地址
func GetCURLIP(ip string) string {
	// IPV6地址在API调用时需要增加[]
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return "[" + ip + "]"
	}
	return ip
}

// 功能：调用其他模块API并获取返回结果
func CURLPerform(method string, url string, body map[string]interface{}) (*simplejson.Json, error) {
	log.Debugf("curl perform: %s %s %+v", method, url, body)
	errResponse, _ := simplejson.NewJson([]byte("{}"))

	// TODO: 通过配置文件获取API超时时间
	client := &http.Client{Timeout: time.Second * 30}

	bodyStr, _ := json.Marshal(&body)
	req, err := http.NewRequest(method, url, bytes.NewReader(bodyStr))
	if err != nil {
		log.Error(err)
		return errResponse, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("X-User-Id", "1")
	req.Header.Set("X-User-Type", "1")

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("curl: %s failed, (%v)", url, err)
		return errResponse, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("curl: %s failed, response detail: %+v", url, resp)
		if respBytes, err := ioutil.ReadAll(resp.Body); err == nil {
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

	respBytes, err := ioutil.ReadAll(resp.Body)
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
	if optStatus != "" && optStatus != httpcommon.SUCCESS {
		description := response.Get("DESCRIPTION").MustString()
		log.Errorf("curl: %s failed, (%s)", url, description)
		e := httpcommon.ErrorFail
		// PENDING used for api /v1/rpmod/
		if optStatus == "PENDING" {
			e = httpcommon.ErrorPending
		}
		return errResponse, fmt.Errorf("%w, %s", e, description)
	}

	return response, nil
}
