/*
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

package app_log

import (
	"strconv"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/app_log/config"
	"github.com/deepflowio/deepflow/server/ingester/app_log/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/app_log/decoder"
	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

type ApplicationLogger struct {
	Config      *config.Config
	Ckwriter    *ckwriter.CKWriter
	SysLogger   *Logger
	AgentLogger *Logger
	AppLogger   *Logger
}

type Logger struct {
	Config        *config.Config
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
}

func NewApplicationLogger(
	config *config.Config,
	recv *receiver.Receiver,
	platformDataManager *grpc.PlatformDataManager,
) (*ApplicationLogger, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_APPLICATION_LOG_QUEUE)

	ckwriter, err := dbwriter.NewAppLogCKWriter(config)
	if err != nil {
		return nil, err
	}
	sysLogger, err := NewLogger(datatype.MESSAGE_TYPE_SYSLOG, config, manager, recv, platformDataManager, ckwriter)
	if err != nil {
		return nil, err
	}
	agentLogger, err := NewLogger(datatype.MESSAGE_TYPE_AGENT_LOG, config, manager, recv, platformDataManager, ckwriter)
	if err != nil {
		return nil, err
	}
	appLogger, err := NewLogger(datatype.MESSAGE_TYPE_APPLICATION_LOG, config, manager, recv, platformDataManager, ckwriter)
	if err != nil {
		return nil, err
	}

	return &ApplicationLogger{
		Config:      config,
		Ckwriter:    ckwriter,
		SysLogger:   sysLogger,
		AgentLogger: agentLogger,
		AppLogger:   appLogger,
	}, nil
}

func (l *ApplicationLogger) Start() {
	l.Ckwriter.Run()
	l.SysLogger.Start()
	l.AgentLogger.Start()
	l.AppLogger.Start()
}

func (l *ApplicationLogger) Close() error {
	l.SysLogger.Close()
	l.AgentLogger.Close()
	l.AppLogger.Close()
	l.Ckwriter.Close()
	return nil
}

func NewLogger(
	msgType datatype.MessageType,
	config *config.Config,
	manager *dropletqueue.Manager,
	recv *receiver.Receiver,
	platformDataManager *grpc.PlatformDataManager,
	ckwriter *ckwriter.CKWriter,
) (*Logger, error) {

	queueCount := config.DecoderQueueCount
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+msgType.String(),
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(msgType, decodeQueues, queueCount)

	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		logWriter, err := dbwriter.NewAppLogWriter(i, msgType, config, ckwriter)
		if err != nil {
			return nil, err
		}
		platformDatas[i], err = platformDataManager.NewPlatformInfoTable("app-log-" + msgType.String() + "-" + strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			logWriter,
			platformDatas[i],
			config,
		)
	}

	return &Logger{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
	}, nil

}

func (l *Logger) Start() {
	for _, decoder := range l.Decoders {
		go decoder.Run()
	}
	for _, platformData := range l.PlatformDatas {
		platformData.Start()
	}
}

func (l *Logger) Close() error {
	for _, decoder := range l.Decoders {
		decoder.Close()
	}
	for _, platformData := range l.PlatformDatas {
		platformData.ClosePlatformInfoTable()
	}
	return nil
}
