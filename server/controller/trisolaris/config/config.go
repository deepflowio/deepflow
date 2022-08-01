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

package config

import (
	"net"
	"os"

	"github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/controller/common"
)

var log = logging.MustGetLogger("trisolaris/config")

type Chrony struct {
	Host    string `default:"chrony" yaml:"host"`
	Port    uint32 `default:"123" yaml:"port"`
	Timeout uint32 `default:"1" yaml:"timeout"`
}

type Config struct {
	ListenPort               string   `default:"20014" yaml:"listen-port"`
	LogLevel                 string   `default:"info"`
	TsdbIP                   string   `yaml:"tsdb-ip"`
	Chrony                   Chrony   `yaml:"chrony"`
	SelfUpdateUrl            string   `default:"grpc" yaml:"self-update-url"`
	TridentPort              string   `default:"20035" yaml:"trident-port"`
	RemoteApiTimeout         uint16   `default:"30" yaml:"remote-api-timeout"`
	TridentTypeForUnkonwVtap uint16   `default:"0" yaml:"trident-type-for-unkonw-vtap"`
	PlatformVips             []string `yaml:"platform-vips"`
	NodeType                 string   `default:"master" yaml:"node-type"`
	GrpcMaxMessageLength     int      `default:"104857600" yaml:"grpc-max-message-length"`
	RegionDomainPrefix       string   `yaml:"region-domain-prefix"`
	ClearKubernetesTime      int      `default:"600" yaml:"clear-kubernetes-time"`
	NodeIP                   string
	VTapCacheRefreshInterval int    `default:"300" yaml:"vtapcache-refresh-interval"`
	MetaDataRefreshInterval  int    `default:"60" yaml:"metadata-refresh-interval"`
	NodeRefreshInterval      int    `default:"60" yaml:"node-refresh-interval"`
	VTapAutoRegister         bool   `default:"true" yaml:"vtap-auto-register"`
	DefaultTapMode           int    `yaml:"default-tap-mode"`
	BillingMethod            string `default:"license" yaml:"billing-method"`
}

func (c *Config) Convert() {
	nodeIP := os.Getenv(common.NODE_IP_KEY)
	ip := net.ParseIP(nodeIP)
	if ip == nil {
		log.Errorf("IP(%s) address format is incorrect", nodeIP)
	} else {
		c.NodeIP = nodeIP
	}
}
