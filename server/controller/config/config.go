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
	"io/ioutil"
	"os"
	"strconv"

	logging "github.com/op/go-logging"
	"gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/controller/db/clickhouse"
	mysql "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	genesis "github.com/deepflowio/deepflow/server/controller/genesis/config"
	manager "github.com/deepflowio/deepflow/server/controller/manager/config"
	monitor "github.com/deepflowio/deepflow/server/controller/monitor/config"
	statsd "github.com/deepflowio/deepflow/server/controller/statsd/config"
	tagrecorder "github.com/deepflowio/deepflow/server/controller/tagrecorder/config"
	trisolaris "github.com/deepflowio/deepflow/server/controller/trisolaris/config"
)

var log = logging.MustGetLogger("config")

type Roze struct {
	Port    int `default:"20106" yaml:"port"`
	Timeout int `default:"60" yaml:"timeout"`
}

type Specification struct {
	VTapGroupMax               int `default:"1000" yaml:"vtap_group_max"`
	VTapMaxPerGroup            int `default:"10000" yaml:"vtap_max_per_group"`
	AZMaxPerServer             int `default:"10" yaml:"az_max_per_server"`
	DataSourceMax              int `default:"10" yaml:"data_source_max"`
	DataSourceRetentionTimeMax int `default:"1000" yaml:"data_source_retention_time_max"`
}

type DFWebService struct {
	Enabled bool   `default:"false" yaml:"enabled"`
	Host    string `default:"df-web" yaml:"host"`
	Port    int    `default:"20106" yaml:"port"`
	Timeout int    `default:"30" yaml:"timeout"`
}

type ControllerConfig struct {
	LogFile                        string `default:"/var/log/controller.log" yaml:"log-file"`
	LogLevel                       string `default:"info" yaml:"log-level"`
	ListenPort                     int    `default:"20417" yaml:"listen-port"`
	ListenNodePort                 int    `default:"30417" yaml:"listen-node-port"` // TODO union port data type
	MasterControllerName           string `default:"" yaml:"master-controller-name"`
	GrpcMaxMessageLength           int    `default:"104857600" yaml:"grpc-max-message-length"`
	GrpcPort                       string `default:"20035" yaml:"grpc-port"`
	IngesterPort                   string `default:"20033" yaml:"ingester-port"`
	GrpcNodePort                   string `default:"30035" yaml:"grpc-node-port"`
	Kubeconfig                     string `yaml:"kubeconfig"`
	ElectionName                   string `default:"deepflow-server" yaml:"election-name"`
	ReportingDisabled              bool   `default:"false" yaml:"reporting-disabled"`
	BillingMethod                  string `default:"license" yaml:"billing-method"`
	PodClusterInternalIPToIngester int    `default:"0" yaml:"pod-cluster-internal-ip-to-ingester"`

	DFWebService DFWebService `yaml:"df-web-service"`

	MySqlCfg      mysql.MySqlConfig           `yaml:"mysql"`
	RedisCfg      redis.RedisConfig           `yaml:"redis"`
	ClickHouseCfg clickhouse.ClickHouseConfig `yaml:"clickhouse"`

	Roze Roze          `yaml:"roze"`
	Spec Specification `yaml:"spec"`

	MonitorCfg     monitor.MonitorConfig         `yaml:"monitor"`
	ManagerCfg     manager.ManagerConfig         `yaml:"manager"`
	GenesisCfg     genesis.GenesisConfig         `yaml:"genesis"`
	StatsdCfg      statsd.StatsdConfig           `yaml:"statsd"`
	TrisolarisCfg  trisolaris.Config             `yaml:"trisolaris"`
	TagRecorderCfg tagrecorder.TagRecorderConfig `yaml:"tagrecorder"`
}

type Config struct {
	ControllerConfig ControllerConfig `yaml:"controller"`
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) Load(path string) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Read config file error:", err, path)
		os.Exit(1)
	}

	if err = yaml.Unmarshal(configBytes, &c); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = c.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	c.ControllerConfig.TrisolarisCfg.SetLogLevel(c.ControllerConfig.LogLevel)
	c.ControllerConfig.TrisolarisCfg.SetBillingMethod(c.ControllerConfig.BillingMethod)
	c.ControllerConfig.TrisolarisCfg.SetPodClusterInternalIPToIngester(c.ControllerConfig.PodClusterInternalIPToIngester)
	c.ControllerConfig.TrisolarisCfg.SetGrpcMaxMessageLength(c.ControllerConfig.GrpcMaxMessageLength)
	grpcPort, err := strconv.Atoi(c.ControllerConfig.GrpcPort)
	if err == nil {
		c.ControllerConfig.TrisolarisCfg.SetGrpcPort(grpcPort)
	}
	ingesterPort, err := strconv.Atoi(c.ControllerConfig.IngesterPort)
	if err == nil {
		c.ControllerConfig.TrisolarisCfg.SetIngesterPort(ingesterPort)
	}
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := SetDefault(cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return cfg
}
