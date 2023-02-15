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

package droplet

import (
	"io"
	"net"
	_ "net/http/pprof"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	libpcap "github.com/deepflowio/deepflow/server/libs/pcap"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/ingester/droplet/adapter"
	"github.com/deepflowio/deepflow/server/ingester/droplet/config"
	"github.com/deepflowio/deepflow/server/ingester/droplet/labeler"
	"github.com/deepflowio/deepflow/server/ingester/droplet/pcap"
	"github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/droplet/statsd"
	"github.com/deepflowio/deepflow/server/ingester/droplet/syslog"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
)

var log = logging.MustGetLogger("droplet")

func Start(cfg *config.Config, recv *receiver.Receiver) (closers []io.Closer) {

	controllers := make([]net.IP, len(cfg.Base.ControllerIPs))
	for i, ipString := range cfg.Base.ControllerIPs {
		ip := net.ParseIP(ipString)
		if ipv4 := ip.To4(); ipv4 == nil {
			controllers[i] = ip
		} else {
			controllers[i] = ipv4
		}
	}

	cleaner := libpcap.NewCleaner(5*time.Minute, int64(cfg.PCap.MaxDirectorySizeGB)<<30, int64(cfg.PCap.DiskFreeSpaceMarginGB)<<30, cfg.PCap.FileDirectory)
	cleaner.Start()

	// L1 - packet source from tridentAdapter
	manager := queue.NewManager(ingesterctl.INGESTERCTL_QUEUE)

	statsdRecvQueues := manager.NewQueues(
		"1-receiver-to-statsd", cfg.Queue.StatsdQueueSize, 1, 1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }),
	)
	syslogRecvQueues := manager.NewQueues(
		"1-receiver-to-syslog", cfg.Queue.SyslogQueueSize, 1, 1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }),
	)
	compressedPacketRecvQueues := manager.NewQueues(
		"1-receiver-to-meta-packet", cfg.Queue.CompressedQueueSize, 1, 1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }),
	)

	recv.RegistHandler(datatype.MESSAGE_TYPE_SYSLOG, syslogRecvQueues, 1)
	recv.RegistHandler(datatype.MESSAGE_TYPE_STATSD, statsdRecvQueues, 1)
	recv.RegistHandler(datatype.MESSAGE_TYPE_COMPRESS, compressedPacketRecvQueues, 1)

	syslog.NewSyslogWriter(syslogRecvQueues.Readers()[0], cfg.AgentLogToFile, cfg.ESSyslog, cfg.SyslogDirectory, cfg.ESHostPorts, cfg.ESAuth.User, cfg.ESAuth.Password)
	statsd.NewStatsdWriter(statsdRecvQueues.Readers()[0])

	releaseMetaPacketBlock := func(x interface{}) {
		datatype.ReleaseMetaPacketBlock(x.(*datatype.MetaPacketBlock))
	}
	labelerQueues := manager.NewQueues(
		"2-meta-packet-block-to-labeler", cfg.Queue.PacketQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionRelease(releaseMetaPacketBlock),
	)
	tridentAdapter := adapter.NewTridentAdapter(compressedPacketRecvQueues.Readers()[0], labelerQueues.Writers(), cfg.Adapter.OrderingCacheSize)
	if tridentAdapter == nil {
		return
	}

	pcapAppQueues := manager.NewQueues(
		"3-meta-packet-block-to-pcap-app", cfg.Queue.PacketQueueSize, cfg.Queue.PacketQueueCount, cfg.Queue.PacketQueueCount,
		libqueue.OptionFlushIndicator(time.Second*10), libqueue.OptionRelease(releaseMetaPacketBlock),
	)

	// labeler
	labelerManager := labeler.NewLabelerManager(labelerQueues.Readers(), pcapAppQueues.Writers(),
		cfg.Queue.PacketQueueCount, cfg.Labeler.Level, cfg.Labeler.MapSizeLimit, cfg.Labeler.FastPathDisable)
	labelerManager.Start()

	if len(controllers) > 0 {
		synchronizer := config.NewRpcConfigSynchronizer(controllers, cfg.Base.ControllerPort, cfg.RpcTimeout, cfg.Base.GrpcBufferSize)
		synchronizer.Register(func(response *trident.SyncResponse, version *config.RpcInfoVersions) {
			log.Debug(response, version)
			cleaner.UpdatePcapDataRetention(time.Duration(response.Config.GetPcapDataRetention()) * time.Hour * 24)
			// Labeler更新策略信息
			labelerManager.OnAclDataChange(response)
		})
		synchronizer.Start()
	}

	pcapClosers := pcap.NewWorkerManager(
		pcapAppQueues.Readers(),
		pcapAppQueues.Writers(),
		cfg.PCap.TCPIPChecksum,
		cfg.PCap.BlockSizeKB,
		cfg.PCap.MaxConcurrentFiles,
		cfg.PCap.MaxFileSizeMB,
		cfg.PCap.MaxFilePeriodSecond,
		cfg.PCap.MaxDirectorySizeGB,
		cfg.PCap.DiskFreeSpaceMarginGB,
		cfg.PCap.FileDirectory,
	).Start()
	closers = append(closers, pcapClosers...)
	// 其他所有组件启动完成以后运行TridentAdapter，尽量避免启动过程中队列丢包
	tridentAdapter.Start()
	return
}
