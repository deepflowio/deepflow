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

package event

import (
	"fmt"
	"strconv"
	"time"

	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/event/decoder"
	"github.com/deepflowio/deepflow/server/ingester/exporters"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

type Event struct {
	Config          *config.Config
	ResourceEventor *Eventor
	PerfEventor     *Eventor
	AlarmEventor    *Eventor
	K8sEventor      *Eventor
}

type Eventor struct {
	Config        *config.Config
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
}

func NewEvent(config *config.Config, resourceEventQueue *queue.OverwriteQueue, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager, exporters *exporters.Exporters) (*Event, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_EVENT_QUEUE)
	resourceEventor, err := NewResouceEventor(resourceEventQueue, config, platformDataManager.GetMasterPlatformInfoTable())
	if err != nil {
		return nil, err
	}

	perfEventor, err := NewEventor(common.PERF_EVENT, config, recv, manager, platformDataManager, exporters)
	if err != nil {
		return nil, err
	}

	alarmEventor, err := NewAlarmEventor(config, recv, manager, platformDataManager.GetMasterPlatformInfoTable())
	if err != nil {
		return nil, err
	}

	k8sEventor, err := NewEventor(common.K8S_EVENT, config, recv, manager, platformDataManager, nil)
	if err != nil {
		return nil, err
	}

	return &Event{
		Config:          config,
		ResourceEventor: resourceEventor,
		PerfEventor:     perfEventor,
		AlarmEventor:    alarmEventor,
		K8sEventor:      k8sEventor,
	}, nil
}

func NewResouceEventor(eventQueue *queue.OverwriteQueue, config *config.Config, platformTable *grpc.PlatformInfoTable) (*Eventor, error) {
	eventWriter, err := dbwriter.NewEventWriter(common.RESOURCE_EVENT, 0, config)
	if err != nil {
		return nil, err
	}
	d := decoder.NewDecoder(
		0,
		common.RESOURCE_EVENT,
		queue.QueueReader(eventQueue),
		eventWriter,
		platformTable,
		nil,
		config,
	)
	return &Eventor{
		Config:   config,
		Decoders: []*decoder.Decoder{d},
	}, nil
}

func NewAlarmEventor(config *config.Config, recv *receiver.Receiver, manager *dropletqueue.Manager, platformTable *grpc.PlatformInfoTable) (*Eventor, error) {
	eventMsg := datatype.MESSAGE_TYPE_ALARM_EVENT
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+eventMsg.String(),
		2<<17, // 128k, default alarm event queue-size
		1,     // default alarm event queue-count
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(eventMsg, decodeQueues, 1)

	eventWriter, err := dbwriter.NewAlarmEventWriter(config)
	if err != nil {
		return nil, err
	}
	d := decoder.NewDecoder(
		0,
		common.ALARM_EVENT,
		queue.QueueReader(decodeQueues.FixedMultiQueue[0]),
		eventWriter,
		platformTable,
		nil,
		config,
	)
	return &Eventor{
		Config:   config,
		Decoders: []*decoder.Decoder{d},
	}, nil
}

func NewEventor(eventType common.EventType, config *config.Config, recv *receiver.Receiver, manager *dropletqueue.Manager, platformDataManager *grpc.PlatformDataManager, exporters *exporters.Exporters) (*Eventor, error) {
	var queueCount, queueSize int
	var msgType datatype.MessageType

	switch eventType {
	case common.PERF_EVENT:
		queueCount = config.PerfDecoderQueueCount
		queueSize = config.PerfDecoderQueueSize
		msgType = datatype.MESSAGE_TYPE_PROC_EVENT
	case common.K8S_EVENT:
		queueCount = config.K8sDecoderQueueCount
		queueSize = config.K8sDecoderQueueSize
		msgType = datatype.MESSAGE_TYPE_K8S_EVENT
	default:
		return nil, fmt.Errorf("unsupport event %s", eventType)
	}

	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+eventType.String(),
		queueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(msgType, decodeQueues, queueCount)

	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		eventWriter, err := dbwriter.NewEventWriter(eventType, i, config)
		if err != nil {
			return nil, err
		}
		platformDatas[i], err = platformDataManager.NewPlatformInfoTable("event-" + eventType.String() + "-" + strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		decoders[i] = decoder.NewDecoder(
			i,
			eventType,
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			eventWriter,
			platformDatas[i],
			exporters,
			config,
		)
	}
	return &Eventor{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
	}, nil
}

func (e *Eventor) Start() {
	for _, decoder := range e.Decoders {
		go decoder.Run()
	}
	for _, platformData := range e.PlatformDatas {
		platformData.Start()
	}
}

func (e *Eventor) Close() {
	for _, decoder := range e.Decoders {
		decoder.Close()
	}
	for _, platformData := range e.PlatformDatas {
		platformData.ClosePlatformInfoTable()
	}
}

func (e *Event) Start() {
	e.ResourceEventor.Start()
	e.PerfEventor.Start()
	e.AlarmEventor.Start()
	e.K8sEventor.Start()
}

func (e *Event) Close() error {
	e.ResourceEventor.Close()
	e.PerfEventor.Close()
	e.AlarmEventor.Close()
	e.K8sEventor.Close()
	return nil
}
