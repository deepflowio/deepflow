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

package ingester

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/deepflowys/deepflow/server/ingester/ckmonitor"
	"github.com/deepflowys/deepflow/server/ingester/datasource"
	"github.com/deepflowys/deepflow/server/libs/datatype"
	"github.com/deepflowys/deepflow/server/libs/debug"
	"github.com/deepflowys/deepflow/server/libs/logger"
	"github.com/deepflowys/deepflow/server/libs/pool"
	"github.com/deepflowys/deepflow/server/libs/receiver"
	"github.com/deepflowys/deepflow/server/libs/stats"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowys/deepflow/server/ingester/ckissu"
	"github.com/deepflowys/deepflow/server/ingester/common"
	"github.com/deepflowys/deepflow/server/ingester/config"
	dropletcfg "github.com/deepflowys/deepflow/server/ingester/droplet/config"
	"github.com/deepflowys/deepflow/server/ingester/droplet/droplet"
	"github.com/deepflowys/deepflow/server/ingester/droplet/profiler"
	extmetricscfg "github.com/deepflowys/deepflow/server/ingester/ext_metrics/config"
	"github.com/deepflowys/deepflow/server/ingester/ext_metrics/ext_metrics"
	"github.com/deepflowys/deepflow/server/ingester/ingesterctl"
	rozecfg "github.com/deepflowys/deepflow/server/ingester/roze/config"
	"github.com/deepflowys/deepflow/server/ingester/roze/roze"
	streamcfg "github.com/deepflowys/deepflow/server/ingester/stream/config"
	"github.com/deepflowys/deepflow/server/ingester/stream/stream"
)

var log = logging.MustGetLogger("ingester")

const (
	INFLUXDB_RELAY_PORT = 20048
	PROFILER_PORT       = 9526
)

func Start(configPath string) []io.Closer {
	logger.EnableStdoutLog()

	cfg := config.Load(configPath)
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Ingester ==============================")
	log.Infof("ingester base config:\n%s", string(bytes))

	debug.SetIpAndPort(ingesterctl.DEBUG_LISTEN_IP, ingesterctl.DEBUG_LISTEN_PORT)
	debug.NewLogLevelControl()

	profiler := profiler.NewProfiler(PROFILER_PORT)
	if cfg.Profiler {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		profiler.Start()
	}

	if cfg.MaxCPUs > 0 {
		runtime.GOMAXPROCS(cfg.MaxCPUs)
	}

	pool.SetCounterRegisterCallback(func(counter *pool.Counter) {
		tags := stats.OptionStatTags{
			"name":                counter.Name,
			"object_size":         strconv.Itoa(int(counter.ObjectSize)),
			"pool_size_per_cpu":   strconv.Itoa(int(counter.PoolSizePerCPU)),
			"init_full_pool_size": strconv.Itoa(int(counter.InitFullPoolSize)),
		}
		common.RegisterCountableForIngester("pool", counter, tags)
	})
	stats.RegisterGcMonitor()
	stats.SetMinInterval(10 * time.Second)
	stats.SetRemoteType(stats.REMOTE_TYPE_DFSTATSD)
	if cfg.InfluxdbWriterEnabled {
		stats.SetRemoteType(stats.REMOTE_TYPE_DFSTATSD | stats.REMOTE_TYPE_INFLUXDB)
		stats.SetRemotes(net.JoinHostPort(cfg.Influxdb.Host, cfg.Influxdb.Port))
	}
	stats.SetDFRemote(net.JoinHostPort("127.0.0.1", strconv.Itoa(datatype.DROPLET_PORT)))

	dropletConfig := dropletcfg.Load(configPath)
	bytes, _ = yaml.Marshal(dropletConfig)
	log.Infof("droplet config:\n%s", string(bytes))

	receiver := receiver.NewReceiver(datatype.DROPLET_PORT, cfg.UDPReadBuffer, cfg.TCPReadBuffer)

	closers := droplet.Start(dropletConfig, receiver)

	if cfg.StreamRozeEnabled {
		streamConfig := streamcfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(streamConfig)
		log.Infof("stream config:\n%s", string(bytes))

		rozeConfig := rozecfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(rozeConfig)
		log.Infof("roze config:\n%s", string(bytes))

		extMetricsConfig := extmetricscfg.Load(cfg, configPath)
		bytes, _ = yaml.Marshal(extMetricsConfig)
		log.Infof("ext_metrics config:\n%s", string(bytes))

		// 写遥测数据
		roze, err := roze.NewRoze(rozeConfig, receiver)
		checkError(err)
		roze.Start()
		closers = append(closers, roze)

		// 写流日志数据
		stream, err := stream.NewStream(streamConfig, receiver)
		checkError(err)
		stream.Start()
		closers = append(closers, stream)

		// 写ext_metrics数据
		extMetrics, err := ext_metrics.NewExtMetrics(extMetricsConfig, receiver)
		checkError(err)
		extMetrics.Start()
		closers = append(closers, extMetrics)

		// 创建、修改、删除数据源及其存储时长
		ds := datasource.NewDatasourceManager([]string{rozeConfig.Base.CKDB.Primary, rozeConfig.Base.CKDB.Secondary},
			rozeConfig.Base.CKDBAuth.Username, rozeConfig.Base.CKDBAuth.Password, rozeConfig.CKReadTimeout, rozeConfig.ReplicaEnabled,
			cfg.CKS3Storage.Enabled, cfg.CKS3Storage.Volume, cfg.CKS3Storage.TTLTimes)
		ds.Start()
		closers = append(closers, ds)

		// 检查clickhouse的磁盘空间占用，达到阈值时，自动删除老数据
		cm, err := ckmonitor.NewCKMonitor(&cfg.CKDiskMonitor, rozeConfig.Base.CKDB.Primary, rozeConfig.Base.CKDB.Secondary, rozeConfig.Base.CKDBAuth.Username, rozeConfig.Base.CKDBAuth.Password)
		checkError(err)
		cm.Start()
		closers = append(closers, cm)

		// clickhouse表结构变更处理
		issu, err := ckissu.NewCKIssu(rozeConfig.Base.CKDB.Primary, rozeConfig.Base.CKDB.Secondary, rozeConfig.Base.CKDBAuth.Username, rozeConfig.Base.CKDBAuth.Password)
		checkError(err)
		// 等roze,stream初始化建表完成,再执行issu
		time.Sleep(time.Second)
		err = issu.Start()
		checkError(err)
		closers = append(closers, issu)
	}
	// receiver后启动，防止启动后收到数据无法处理，而上报异常日志
	receiver.Start()
	closers = append(closers, receiver)

	return closers
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
