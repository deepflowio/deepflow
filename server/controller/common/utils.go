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
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	logging "github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"
)

var log = logging.MustGetLogger("common")

var osDict = map[string]int{
	"centos":  OS_CENTOS,
	"red hat": OS_REDHAT,
	"redhat":  OS_REDHAT,
	"ubuntu":  OS_UBUNTU,
	"suse":    OS_SUSE,
	"windows": OS_WINDOWS,
}

var archDict = map[string]int{
	"x86":   ARCH_X86,
	"amd64": ARCH_X86,
	"i686":  ARCH_X86,
	"i386":  ARCH_X86,
	"aarch": ARCH_ARM,
	"arm":   ARCH_ARM,
}

var letterRunes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func GetOsType(os string) int {
	for key, value := range osDict {
		if strings.Contains(strings.ToLower(os), key) {
			return value
		}
	}
	return 0
}

func GetArchType(arch string) int {
	for key, value := range archDict {
		if strings.Contains(strings.ToLower(arch), key) {
			return value
		}
	}
	return 0
}

func GenerateUUID(str string) string {
	return uuid.NewV5(uuid.NamespaceOID, str).String()
}

func GenerateShortUUID() string {
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.New(rand.NewSource(time.Now().UnixNano())).Intn(len(letterRunes))]
	}
	return string(b)
}

func GenerateKuberneteClusterIDByMD5(md5 string) (string, error) {

	if len(md5) != 32 {
		errMsg := fmt.Sprintf("md5 (%s) is invaild", md5)
		return "", errors.New(errMsg)
	}

	b2 := make([]rune, 2)
	b8 := make([]rune, 8)
	for i := range b2 {
		randSourceStr := "0x" + md5[i*16:i*16+16]
		randSourceInt, _ := strconv.ParseInt(randSourceStr, 0, 64)
		b2[i] = letterRunes[rand.New(rand.NewSource(randSourceInt)).Intn(len(letterRunes))]
	}
	for i := range b8 {
		randSourceStr := "0x" + md5[i*4:i*4+4]
		randSourceInt, _ := strconv.ParseInt(randSourceStr, 0, 64)
		b8[i] = letterRunes[rand.New(rand.NewSource(randSourceInt)).Intn(len(letterRunes))]
	}
	return "d-" + string(b2) + string(b8), nil
}

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
		log.Errorf("curl (%s) failed, (%v)", url, err)
		return errResponse, err
	} else if resp.StatusCode != http.StatusOK {
		log.Warning("curl (%s) failed, (%v)", url, resp)
		defer resp.Body.Close()
		return errResponse, errors.New(fmt.Sprintf("curl (%s) failed", url))
	}
	defer resp.Body.Close()

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
	if optStatus != "" && optStatus != SUCCESS {
		description := response.Get("DESCRIPTION").MustString()
		log.Errorf("curl (%s) failed, (%s)", url, description)
		return errResponse, errors.New(description)
	}

	return response, nil
}

// 通过字符串获取UUID
func GetUUID(str string, namespace uuid.UUID) string {
	if str != "" {
		if namespace != uuid.Nil {
			return uuid.NewV5(namespace, str).String()
		}
		return uuid.NewV5(uuid.NamespaceOID, str).String()
	}
	if v4, err := uuid.NewV4(); err == nil {
		return v4.String()
	}
	return uuid.NewV5(uuid.NamespaceOID, str).String()
}

func IsValueInSliceString(value string, list []string) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}
