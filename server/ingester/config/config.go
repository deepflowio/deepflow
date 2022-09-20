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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

const (
	DefaultContrallerIP      = "127.0.0.1"
	DefaultControllerPort    = 20035
	DefaultCheckInterval     = 600 // clickhouse是异步删除
	DefaultDiskUsedPercent   = 90
	DefaultDiskFreeSpace     = 50
	DefaultCKDBS3Volume      = "vol_s3"
	DefaultCKDBS3TTLTimes    = 3 // 对象存储的保留时长是本地存储的3倍
	DefaultInfluxdbHost      = "influxdb"
	DefaultInfluxdbPort      = "20044"
	EnvK8sNodeIP             = "K8S_NODE_IP_FOR_DEEPFLOW"
	EnvK8sPodName            = "K8S_POD_NAME_FOR_DEEPFLOW"
	DefaultCKDBServicePrefix = "clickhouse"
	DefaultCKDBServicePort   = 9000
	DefaultListenPort        = 20033
)

type CKDiskMonitor struct {
	CheckInterval int `yaml:"check-interval"` // s
	UsedPercent   int `yaml:"used-percent"`   // 0-100
	FreeSpace     int `yaml:"free-space"`     // Gb
}

type CKS3Storage struct {
	Enabled  bool   `yaml:"enabled"`
	Volume   string `yaml:"volume"`
	TTLTimes int    `yaml:"ttl-times"`
}

type HostPort struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

type CKAddrs struct {
	Primary   string `yaml:"primary"`
	Secondary string `yaml:"secondary"` // 既可以是primary也可以是replica
}

type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type CKWriterConfig struct {
	QueueCount   int `yaml:"queue-count"`
	QueueSize    int `yaml:"queue-size"`
	BatchSize    int `yaml:"batch-size"`
	FlushTimeout int `yaml:"flush-timeout"`
}

type Config struct {
	ListenPort            uint16        `yaml:"listen-port"`
	ControllerIPs         []string      `yaml:"controller-ips,flow"`
	ControllerPort        uint16        `yaml:"controller-port"`
	CKDBServicePrefix     string        `yaml:"ckdb-service-prefix"`
	CKDBServicePort       int           `yaml:"ckdb-service-port"`
	CKDB                  CKAddrs       `yaml:"ckdb"`
	CKDBAuth              Auth          `yaml:"ckdb-auth"`
	StreamRozeEnabled     bool          `yaml:"stream-roze-enabled"`
	UDPReadBuffer         int           `yaml:"udp-read-buffer"`
	TCPReadBuffer         int           `yaml:"tcp-read-buffer"`
	Profiler              bool          `yaml:"profiler"`
	MaxCPUs               int           `yaml:"max-cpus"`
	CKDiskMonitor         CKDiskMonitor `yaml:"ck-disk-monitor"`
	CKS3Storage           CKS3Storage   `yaml:"ckdb-s3"`
	InfluxdbWriterEnabled bool          `yaml:"influxdb-writer-enabled"`
	Influxdb              HostPort      `yaml:"influxdb"`
	NodeIP                string        `yaml:"node-ip"`
	ShardID               int           `yaml:"shard-id"`
	LogFile               string
	LogLevel              string
}

type BaseConfig struct {
	LogFile  string `yaml:"log-file"`
	LogLevel string `yaml:"log-level"`
	Base     Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if len(c.ControllerIPs) == 0 {
		log.Warning("controller-ips is empty")
	} else {
		for _, ipString := range c.ControllerIPs {
			if net.ParseIP(ipString) == nil {
				return errors.New("controller-ips invalid")
			}
		}
	}

	// if the controller IP is localhost, can't get node ip through ip routing,
	// should get node ip from ENV
	if c.NodeIP == "" && c.ControllerIPs[0] == DefaultContrallerIP {
		nodeIP, exist := os.LookupEnv(EnvK8sNodeIP)
		if !exist {
			panic(fmt.Sprintf("Can't get env %s", EnvK8sNodeIP))
		}
		c.NodeIP = nodeIP
	}

	if c.CKDB.Primary == "" {
		podName, exist := os.LookupEnv(EnvK8sPodName)
		if !exist {
			panic(fmt.Sprintf("Can't get pod name env %s", EnvK8sPodName))
		}
		index := strings.LastIndex(podName, "-")
		if index == -1 || index >= len(podName)-1 {
			panic(fmt.Sprintf("pod name is %s,  should cantains '-'", podName))
		}
		indexInt, err := strconv.Atoi(podName[index+1:])
		if err != nil {
			panic(fmt.Sprintf("pod name is %s,  should have digit subfix", podName))
		}
		if c.ShardID == 0 {
			c.ShardID = indexInt
		}
		c.CKDB.Primary = fmt.Sprintf("%s-%d:%d", c.CKDBServicePrefix, indexInt, c.CKDBServicePort)
		log.Infof("get clickhouse address: %s", c.CKDB.Primary)
	}

	if c.CKDB.Primary == c.CKDB.Secondary {
		return errors.New("in 'ckdb' config, 'primary' is equal to 'secondary', it is not allowed")
	}

	level := strings.ToLower(c.LogLevel)
	c.LogLevel = "info"
	for _, l := range []string{"error", "warn", "info", "debug"} {
		if level == l {
			c.LogLevel = l
		}
	}

	return nil
}

func Load(path string) *Config {
	configBytes, err := ioutil.ReadFile(path)
	config := BaseConfig{
		LogFile:  "/var/log/deepflow/server.log",
		LogLevel: "info",
		Base: Config{
			ControllerIPs:     []string{DefaultContrallerIP},
			ControllerPort:    DefaultControllerPort,
			CKDBServicePrefix: DefaultCKDBServicePrefix,
			CKDBServicePort:   DefaultCKDBServicePort,
			StreamRozeEnabled: true,
			UDPReadBuffer:     64 << 20,
			TCPReadBuffer:     4 << 20,
			CKDiskMonitor:     CKDiskMonitor{DefaultCheckInterval, DefaultDiskUsedPercent, DefaultDiskFreeSpace},
			CKS3Storage:       CKS3Storage{false, DefaultCKDBS3Volume, DefaultCKDBS3TTLTimes},
			Influxdb:          HostPort{DefaultInfluxdbHost, DefaultInfluxdbPort},
			ListenPort:        DefaultListenPort,
		},
	}
	if err != nil {
		log.Error("Read config file error:", err)
		os.Exit(1)
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Base.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	config.Base.LogFile = config.LogFile
	config.Base.LogLevel = config.LogLevel
	return &config.Base
}
