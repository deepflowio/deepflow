// Copyright (c) 2024 Yunshan Networks
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"os"
	"strings"
)

var NodeName, NodeIP, PodName, PodIP, NameSpace, runningMode string

func InitEnvData() {
	runningMode = os.Getenv(RUNNING_MODE_KEY)
	if IsStandaloneRunningMode() == true {
		// in standalone mode, currently only NodeIP can be passed through environment variables
		NodeName, _ = os.Hostname()
		NodeIP = os.Getenv(NODE_IP_KEY)
		PodName, _ = os.Hostname()
		PodIP = os.Getenv(POD_IP_KEY)
		if PodIP == "" {
			PodIP = "127.0.0.1"
		}
	} else {
		NodeName = os.Getenv(NODE_NAME_KEY)
		NodeIP = os.Getenv(NODE_IP_KEY)
		PodName = os.Getenv(POD_NAME_KEY)
		PodIP = os.Getenv(POD_IP_KEY)
		NameSpace = os.Getenv(NAME_SPACE_KEY)
	}
	log.Infof("ENV %s=%s; %s=%s; %s=%s; %s=%s; %s=%s, %s=%s",
		NODE_NAME_KEY, NodeName,
		NODE_IP_KEY, NodeIP,
		POD_NAME_KEY, PodName,
		POD_IP_KEY, PodIP,
		NAME_SPACE_KEY, NameSpace,
		RUNNING_MODE_KEY, runningMode)
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
	"centos":     OS_CENTOS,
	"red hat":    OS_REDHAT,
	"redhat":     OS_REDHAT,
	"ubuntu":     OS_UBUNTU,
	"suse":       OS_SUSE,
	"windows":    OS_WINDOWS,
	"cuttlefish": OS_ANDROID,
}

var archDict = map[string]int{
	"x86":   ARCH_X86,
	"amd64": ARCH_X86,
	"i686":  ARCH_X86,
	"i386":  ARCH_X86,
	"aarch": ARCH_ARM,
	"arm":   ARCH_ARM,
}

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

func IsStandaloneRunningMode() bool {
	return runningMode == RUNNING_MODE_STANDALONE
}
