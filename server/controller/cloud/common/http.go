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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/bitly/go-simplejson"
)

func GetUnverifyHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func RequestGet(url, token string, timeout time.Duration) (jsonResp *simplejson.Json, err error) {
	log.Infof("url: %s", url)
	log.Debugf("token: %s", token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("new request failed: %s", err.Error())
		return
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "application/json, text/plain")

	// TODO: 通过配置文件获取API超时时间
	client := GetUnverifyHTTPClient(time.Second * timeout)
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("request failed: %s", err.Error())
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Errorf("request failed: %+v", resp)
		err = errors.New(fmt.Sprintf("request failed: %v", resp))
		return
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("read failed: %s", err.Error())
		return
	}
	jsonResp, err = simplejson.NewJson(respBody)
	if err != nil {
		log.Errorf("jsonify failed: %s", err.Error())
		return
	}
	return
}

func RequestPost(url string, timeout time.Duration, body map[string]interface{}) (jsonResp *simplejson.Json, err error) {
	log.Infof("url: %s", url)
	log.Debugf("body: %+v", body)
	bodyStr, _ := json.Marshal(&body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyStr))
	if err != nil {
		log.Errorf("new request failed: %s", err.Error())
		return
	}
	req.Header.Set("content-type", "application/json")

	// TODO: 通过配置文件获取API超时时间
	client := GetUnverifyHTTPClient(time.Second * timeout)
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("request failed: %s", err.Error())
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Errorf("request failed: %+v", resp)
		err = errors.New(fmt.Sprintf("request failed: %v", resp))
		return
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("read failed: %s", err.Error())
		return
	}
	jsonResp, err = simplejson.NewJson(respBody)
	if err != nil {
		log.Errorf("jsonify failed: %s", err.Error())
		return
	}
	jsonResp.Set("X-Subject-Token", resp.Header.Get("X-Subject-Token"))
	return
}
