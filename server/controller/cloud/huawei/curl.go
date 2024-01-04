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

package huawei

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

func getUnverifiedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func newErr(url, msg string) error {
	return errors.New(fmt.Sprintf("request url: %s, %s", url, msg))
}

func RequestGet(url, token string, timeout time.Duration, header map[string]string) (jsonResp *simplejson.Json, err error) {
	log.Debugf("url: %s", url)
	log.Debugf("token: %s", token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		err = newErr(url, fmt.Sprintf("new request failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "application/json, text/plain")
	for k, v := range header {
		req.Header.Set(k, v)
	}

	client := getUnverifiedHTTPClient(time.Second * timeout)
	resp, err := client.Do(req)
	if err != nil {
		err = newErr(url, fmt.Sprintf("failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = newErr(url, fmt.Sprintf("failed: %v", resp))
		log.Errorf(err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = newErr(url, fmt.Sprintf("read failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	jsonResp, err = simplejson.NewJson(respBody)
	if err != nil {
		err = newErr(url, fmt.Sprintf("JSONiz failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	return
}

func RequestPost(url string, timeout time.Duration, body map[string]interface{}) (jsonResp *simplejson.Json, err error) {
	log.Debugf("url: %s", url)
	log.Debugf("body: %+v", body)
	bodyStr, _ := json.Marshal(&body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyStr))
	if err != nil {
		err = newErr(url, fmt.Sprintf("new request failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	req.Header.Set("content-type", "application/json")

	client := getUnverifiedHTTPClient(time.Second * timeout)
	resp, err := client.Do(req)
	if err != nil {
		err = newErr(url, fmt.Sprintf("failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		err = newErr(url, fmt.Sprintf("failed: %v", resp))
		log.Errorf(err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = newErr(url, fmt.Sprintf("read failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	jsonResp, err = simplejson.NewJson(respBody)
	if err != nil {
		err = newErr(url, fmt.Sprintf("JSONiz failed: %s", err.Error()))
		log.Errorf(err.Error())
		return
	}
	jsonResp.Set("X-Subject-Token", resp.Header.Get("X-Subject-Token"))
	return
}
