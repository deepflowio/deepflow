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
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	logging "github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var log = logging.MustGetLogger("common")

var NodeName, NodeIP, PodName, PodIP, NameSpace string

func init() {
	NodeName = os.Getenv(NODE_NAME_KEY)
	NodeIP = os.Getenv(NODE_IP_KEY)
	PodName = os.Getenv(POD_NAME_KEY)
	PodIP = os.Getenv(POD_IP_KEY)
	NameSpace = os.Getenv(NAME_SPACE_KEY)
	log.Infof("ENV %s=%s; %s=%s; %s=%s; %s=%s; %s=%s",
		NODE_NAME_KEY, NodeName,
		NODE_IP_KEY, NodeIP,
		POD_NAME_KEY, PodName,
		POD_IP_KEY, PodIP,
		NAME_SPACE_KEY, NameSpace)
}

func GetNodeName() string {
	return NodeName
}

func GetNodeIP() string {
	return NodeIP
}

func GetPodName() string {
	return PodName
}

func GetPodIP() string {
	return PodIP
}

func GetNameSpace() string {
	return NameSpace
}

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

var (
	letterRunes                 = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	vtapGroupShortUUIDRegexp, _ = regexp.Compile(`^g-[A-Za-z0-9]{10}$`)
)

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

const SHORT_UUID_LENGTH int = 10

func GenerateShortUUID() string {
	b := make([]rune, SHORT_UUID_LENGTH)
	for i := range b {
		b[i] = letterRunes[rand.New(rand.NewSource(time.Now().UnixNano())).Intn(len(letterRunes))]
	}
	return string(b)
}

// IsVtapGroupShortUUID checks uuid consists of numbers and English letters with g- prefix.
func IsVtapGroupShortUUID(uuid string) bool {
	result := vtapGroupShortUUIDRegexp.FindAllStringSubmatch(uuid, -1)
	return len(result) != 0
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
	if optStatus != "" && optStatus != SUCCESS {
		description := response.Get("DESCRIPTION").MustString()
		log.Errorf("curl: %s failed, (%s)", url, description)
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

func GetCurrentControllerIP() string {
	return os.Getenv(NODE_IP_KEY)
}

func GetCurrentController() (*mysql.Controller, error) {
	controllerIP := GetCurrentControllerIP()
	var controller *mysql.Controller
	err := mysql.Db.Where("ip = ?", controllerIP).Find(&controller).Error
	return controller, err
}

func GetMasterControllerHostPort() (masterIP string, httpPort, grpcPort int, err error) {
	var host string
	curController, err := GetCurrentController()
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

func GetVTapSubDomainMappingByDomain(domain string) (map[int]string, error) {
	vtapIDToSubDomain := make(map[int]string)

	var azs []mysql.AZ
	err := mysql.Db.Where("domain = ?", domain).Find(&azs).Error
	if err != nil {
		return vtapIDToSubDomain, err
	}
	azLcuuids := []string{}
	for _, az := range azs {
		azLcuuids = append(azLcuuids, az.Lcuuid)
	}

	var podNodes []mysql.PodNode
	err = mysql.Db.Where("domain = ?", domain).Find(&podNodes).Error
	if err != nil {
		return vtapIDToSubDomain, err
	}
	podNodeIDToSubDomain := make(map[int]string)
	for _, podNode := range podNodes {
		podNodeIDToSubDomain[podNode.ID] = podNode.SubDomain
	}

	var vtaps []mysql.VTap
	err = mysql.Db.Where("az IN ?", azLcuuids).Find(&vtaps).Error
	if err != nil {
		return vtapIDToSubDomain, err
	}
	for _, vtap := range vtaps {
		vtapIDToSubDomain[vtap.ID] = ""
		if vtap.Type == VTAP_TYPE_POD_HOST || vtap.Type == VTAP_TYPE_POD_VM {
			if subDomain, ok := podNodeIDToSubDomain[vtap.LaunchServerID]; ok {
				vtapIDToSubDomain[vtap.ID] = subDomain
			}
		}
	}

	return vtapIDToSubDomain, nil
}

func IsTCPActive(ip string, port int) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return err
	} else {
		if conn != nil {
			conn.Close()
		} else {
			return fmt.Errorf("check tcp alive failed (ip:%s, port:%d)", ip, port)
		}
	}
	return nil
}
