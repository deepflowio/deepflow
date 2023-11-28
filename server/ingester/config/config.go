/*
 * Copyright (c) 2023 Yunshan Networks
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
	"strings"
	"time"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

var log = logging.MustGetLogger("config")

const (
	DefaultControllerIP             = "127.0.0.1"
	DefaultControllerPort           = 20035
	DefaultCheckInterval            = 300 // clickhouse是异步删除
	DefaultDiskUsedPercent          = 80
	DefaultDiskFreeSpace            = 100
	DefaultDFDiskPrefix             = "path_" // In the config.xml of ClickHouse, the disk name of the storage policy 'df_storage' written by deepflow-server starts with 'path_'
	EnvK8sNodeIP                    = "K8S_NODE_IP_FOR_DEEPFLOW"
	EnvK8sPodName                   = "K8S_POD_NAME_FOR_DEEPFLOW"
	EnvK8sNodeName                  = "K8S_NODE_NAME_FOR_DEEPFLOW"
	EnvK8sNamespace                 = "K8S_NAMESPACE_FOR_DEEPFLOW"
	DefaultCKDBService              = "deepflow-clickhouse"
	DefaultCKDBServicePort          = 9000
	DefaultListenPort               = 20033
	DefaultGrpcBufferSize           = 41943040
	DefaultServiceLabelerLruCap     = 1 << 22
	DefaultCKDBEndpointTCPPortName  = "tcp-port"
	DefaultStatsInterval            = 10      // s
	DefaultFlowTagCacheFlushTimeout = 1800    // s
	DefaultFlowTagCacheMaxSize      = 1 << 18 // 256k
)

type DatabaseTable struct {
	Database      string `yaml:"database"`
	TablesContain string `yaml:"tables-contain"`
}

type DiskCleanup struct {
	DiskNamePrefix string `yaml:"disk-name-prefix"`
	UsedPercent    int    `yaml:"used-percent"` // 0-100
	FreeSpace      int    `yaml:"free-space"`   // Gb
	UsedSpace      int    `yaml:"used-space"`   // Gb
}

type CKDiskMonitor struct {
	CheckInterval int             `yaml:"check-interval"` // s
	DiskCleanups  []DiskCleanup   `yaml:"disk-cleanups"`
	PriorityDrops []DatabaseTable `yaml:"priority-drops"`
}

type Disk struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}

type StorageSetting struct {
	Db        string   `yaml:"db"`
	Tables    []string `yaml:"tables,flow"`
	TTLToMove int      `yaml:"ttl-hour-to-move"`
}

type CKDBColdStorage struct {
	Enabled  bool             `yaml:"enabled"`
	ColdDisk Disk             `yaml:"cold-disk"`
	Settings []StorageSetting `yaml:"settings,flow"`
}

type HostPort struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
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

type PromWriterConfig struct {
	Enabled       bool              `yaml:"enabled"`
	Endpoint      string            `yaml:"endpoint"`
	Headers       map[string]string `yaml:"headers"`
	BatchSize     int               `yaml:"batch-size"`
	FlushTimeout  int               `yaml:"flush-timeout"`
	Concurrency   int               `yaml:"concurrency"`
	MetricsFilter []string          `yaml:"metrics-filter"`
}

type CKDB struct {
	External            bool   `yaml:"external"`
	Host                string `yaml:"host"`
	ActualAddrs         []string
	Watcher             *Watcher
	Port                int    `yaml:"port"`
	EndpointTCPPortName string `yaml:"endpoint-tcp-port-name"`
	ClusterName         string `yaml:"cluster-name"`
	StoragePolicy       string `yaml:"storage-policy"`
	TimeZone            string `yaml:"time-zone"`
}

type Config struct {
	StorageDisabled          bool            `yaml:"storage-disabled"`
	ListenPort               uint16          `yaml:"listen-port"`
	CKDB                     CKDB            `yaml:"ckdb"`
	ControllerIPs            []string        `yaml:"controller-ips,flow"`
	ControllerPort           uint16          `yaml:"controller-port"`
	CKDBAuth                 Auth            `yaml:"ckdb-auth"`
	IngesterEnabled          bool            `yaml:"ingester-enabled"`
	UDPReadBuffer            int             `yaml:"udp-read-buffer"`
	TCPReadBuffer            int             `yaml:"tcp-read-buffer"`
	TCPReaderBuffer          int             `yaml:"tcp-reader-buffer"`
	CKDiskMonitor            CKDiskMonitor   `yaml:"ck-disk-monitor"`
	ColdStorage              CKDBColdStorage `yaml:"ckdb-cold-storage"`
	ckdbColdStorages         map[string]*ckdb.ColdStorage
	NodeIP                   string `yaml:"node-ip"`
	GrpcBufferSize           int    `yaml:"grpc-buffer-size"`
	ServiceLabelerLruCap     int    `yaml:"service-labeler-lru-cap"`
	StatsInterval            int    `yaml:"stats-interval"`
	FlowTagCacheFlushTimeout uint32 `yaml:"flow-tag-cache-flush-timeout"`
	FlowTagCacheMaxSize      uint32 `yaml:"flow-tag-cache-max-size"`
	LogFile                  string
	LogLevel                 string
	MyNodeName               string
}

type BaseConfig struct {
	LogFile  string `yaml:"log-file"`
	LogLevel string `yaml:"log-level"`
	Base     Config `yaml:"ingester"`
}

func sleepAndExit() {
	time.Sleep(time.Second)
	os.Exit(1)
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

	if c.FlowTagCacheMaxSize == 0 {
		c.FlowTagCacheMaxSize = DefaultFlowTagCacheMaxSize
	}
	if c.FlowTagCacheFlushTimeout == 0 {
		c.FlowTagCacheFlushTimeout = DefaultFlowTagCacheFlushTimeout
	}

	level := strings.ToLower(c.LogLevel)
	c.LogLevel = "info"
	for _, l := range []string{"error", "warn", "info", "debug"} {
		if level == l {
			c.LogLevel = l
		}
	}

	if c.GrpcBufferSize <= 0 {
		c.GrpcBufferSize = DefaultGrpcBufferSize
	}

	if c.ServiceLabelerLruCap <= 0 {
		c.ServiceLabelerLruCap = DefaultServiceLabelerLruCap
	}

	if c.StatsInterval <= 0 {
		c.StatsInterval = DefaultStatsInterval
	}

	// should get node ip from ENV
	if c.NodeIP == "" && c.ControllerIPs[0] == DefaultControllerIP {
		nodeIP, exist := os.LookupEnv(EnvK8sNodeIP)
		if !exist {
			log.Errorf("Can't get env %s", EnvK8sNodeIP)
			sleepAndExit()
		}
		c.NodeIP = nodeIP
	}

	myNodeName, exist := os.LookupEnv(EnvK8sNodeName)
	if !exist {
		log.Errorf("Can't get node name env %s", EnvK8sNodeName)
		sleepAndExit()
	}
	c.MyNodeName = myNodeName

	if c.StorageDisabled {
		return nil
	}

	myPodName, exist := os.LookupEnv(EnvK8sPodName)
	if !exist {
		log.Errorf("Can't get pod name env %s", EnvK8sPodName)
		sleepAndExit()
	}
	myNamespace, exist := os.LookupEnv(EnvK8sNamespace)
	if !exist {
		log.Errorf("Can't get pod namespace env %s", EnvK8sNamespace)
		sleepAndExit()
	}

	if c.CKDB.Host == "" {
		c.CKDB.Host = DefaultCKDBService
	}
	if c.CKDB.Port == 0 {
		c.CKDB.Port = DefaultCKDBServicePort
	}
	if c.CKDB.EndpointTCPPortName == "" {
		c.CKDB.EndpointTCPPortName = DefaultCKDBEndpointTCPPortName
	}
	if c.CKDB.ClusterName == "" {
		if c.CKDB.External {
			c.CKDB.ClusterName = "default"
		} else {
			c.CKDB.ClusterName = ckdb.DF_CLUSTER
		}
	}
	if c.CKDB.StoragePolicy == "" {
		if c.CKDB.External {
			c.CKDB.StoragePolicy = "default"
		} else {
			c.CKDB.StoragePolicy = ckdb.DF_STORAGE_POLICY
		}
	}
	if c.CKDB.TimeZone == "" {
		c.CKDB.TimeZone = ckdb.DF_TIMEZONE
	}

	var watcher *Watcher
	var err error
	for retryTimes := 0; ; retryTimes++ {
		if retryTimes > 0 {
			time.Sleep(time.Second * 30)
		}
		if watcher == nil {
			watcher, err = NewWatcher(myNodeName, myPodName, myNamespace, c.CKDB.Host, c.CKDB.EndpointTCPPortName, c.CKDB.External, c.ControllerIPs, int(c.ControllerPort), c.GrpcBufferSize)
			if err != nil {
				log.Warningf("get kubernetes watcher failed %s", err)
				continue
			}
		}

		endpoints, err := watcher.GetMyClickhouseEndpoints()
		if err != nil {
			log.Warningf("get clickhouse endpoints(%s) failed, err: %s", c.CKDB.Host, err)
			continue
		}
		c.CKDB.ActualAddrs = c.CKDB.ActualAddrs[:0]
		for _, endpoint := range endpoints {
			// if it is an IPv6 address, it needs to be enclosed in []
			if strings.Contains(endpoint.Host, ":") {
				c.CKDB.ActualAddrs = append(c.CKDB.ActualAddrs, fmt.Sprintf("[%s]:%d", endpoint.Host, endpoint.Port))
			} else {
				c.CKDB.ActualAddrs = append(c.CKDB.ActualAddrs, fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port))
			}
		}
		c.CKDB.Watcher = watcher
		log.Infof("get clickhouse actual address: %s", c.CKDB.ActualAddrs)

		conns, err := common.NewCKConnections(c.CKDB.ActualAddrs, c.CKDBAuth.Username, c.CKDBAuth.Password)
		if err != nil {
			log.Warningf("connect to clickhouse %s failed, err: %s", c.CKDB.ActualAddrs, err)
			continue
		}

		if err := CheckCluster(conns, c.CKDB.ClusterName); err != nil {
			log.Errorf("get clickhouse cluster(%s) info from table 'system.clusters' failed, err: %s", c.CKDB.ClusterName, err)
			continue
		}

		if err := CheckStoragePolicy(conns, c.CKDB.StoragePolicy); err != nil {
			log.Errorf("get clickhouse storage policy(%s) info from table 'system.storage_polices' failed, err: %s", c.CKDB.StoragePolicy, err)
			continue
		}
		break
	}

	return c.ValidateAndSetckdbColdStorages()
}

func (c *Config) ValidateAndSetckdbColdStorages() error {
	c.ckdbColdStorages = make(map[string]*ckdb.ColdStorage)
	if !c.ColdStorage.Enabled {
		return nil
	}

	var diskType ckdb.DiskType
	if c.ColdStorage.ColdDisk.Type == "disk" {
		diskType = ckdb.Disk
	} else if c.ColdStorage.ColdDisk.Type == "volume" {
		diskType = ckdb.Volume
	} else {
		return fmt.Errorf("'ingester.ckdb-cold-storage.cold-disk.type' is '%s', should be 'volume' or 'disk'", c.ColdStorage.ColdDisk.Type)
	}

	if c.ColdStorage.ColdDisk.Name == "" {
		return errors.New("'ingester.ckdb-cold-storage.cold-disk.name' is empty")
	}

	for i, setting := range c.ColdStorage.Settings {
		if setting.Db == "" {
			return fmt.Errorf("'ingester.ckdb-cold-storage.settings[%d].db' is empty", i)
		}
		if setting.TTLToMove < 1 {
			return fmt.Errorf("'ingester.ckdb-cold-storage.settings[%d].ttl-hour-to-move' is '%d', should > 0", i, setting.TTLToMove)
		}
		for _, table := range setting.Tables {
			c.ckdbColdStorages[setting.Db+table] = &ckdb.ColdStorage{
				Enabled:   true,
				Type:      diskType,
				Name:      c.ColdStorage.ColdDisk.Name,
				TTLToMove: setting.TTLToMove,
			}
		}
		// If only 'db' is configured and 'tables' is not configured, then the same settings are made to the tables under db
		if len(c.ckdbColdStorages) == 0 {
			c.ckdbColdStorages[setting.Db] = &ckdb.ColdStorage{
				Enabled:   true,
				Type:      diskType,
				Name:      c.ColdStorage.ColdDisk.Name,
				TTLToMove: setting.TTLToMove,
			}
		}
	}
	return nil
}

func (c *Config) GetCKDBColdStorages() map[string]*ckdb.ColdStorage {
	return c.ckdbColdStorages
}

func Load(path string) *Config {
	configBytes, err := ioutil.ReadFile(path)
	config := BaseConfig{
		LogFile:  "/var/log/deepflow/server.log",
		LogLevel: "info",
		Base: Config{
			ControllerIPs:   []string{DefaultControllerIP},
			ControllerPort:  DefaultControllerPort,
			CKDBAuth:        Auth{"default", ""},
			IngesterEnabled: true,
			UDPReadBuffer:   64 << 20,
			TCPReadBuffer:   4 << 20,
			TCPReaderBuffer: 1 << 20,
			CKDiskMonitor: CKDiskMonitor{
				DefaultCheckInterval,
				[]DiskCleanup{
					{
						DefaultDFDiskPrefix,
						DefaultDiskUsedPercent,
						DefaultDiskFreeSpace,
						0,
					},
				},
				[]DatabaseTable{{"flow_log", ""}, {"flow_metrics", "1s_local"}},
			},
			ListenPort:               DefaultListenPort,
			GrpcBufferSize:           DefaultGrpcBufferSize,
			ServiceLabelerLruCap:     DefaultServiceLabelerLruCap,
			StatsInterval:            DefaultStatsInterval,
			FlowTagCacheFlushTimeout: DefaultFlowTagCacheFlushTimeout,
			FlowTagCacheMaxSize:      DefaultFlowTagCacheMaxSize,
		},
	}
	if err != nil {
		log.Error("Read config file error:", err)
		sleepAndExit()
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		sleepAndExit()
	}

	if err = config.Base.Validate(); err != nil {
		log.Error(err)
		sleepAndExit()
	}
	config.Base.LogFile = config.LogFile
	config.Base.LogLevel = config.LogLevel
	return &config.Base
}

func CheckCluster(conns common.DBs, clusterName string) error {
	sql := fmt.Sprintf("SELECT host_address,port FROM system.clusters WHERE cluster='%s'", clusterName)
	rows, err := conns.Query(sql)
	if err != nil {
		return err
	}
	var addr string
	var port uint16
	for rows.Next() {
		return rows.Scan(&addr, &port)
	}

	return fmt.Errorf("cluster '%s' not find", clusterName)
}

func CheckStoragePolicy(conns common.DBs, storagePolicy string) error {
	sql := fmt.Sprintf("SELECT policy_name FROM system.storage_policies WHERE policy_name='%s'", storagePolicy)
	rows, err := conns.Query(sql)
	if err != nil {
		return err
	}
	var policyName string
	for rows.Next() {
		return rows.Scan(&policyName)
	}
	return fmt.Errorf("storage policy '%s' not find", storagePolicy)
}
