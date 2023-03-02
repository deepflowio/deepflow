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

package event

import (
	"strconv"
	"time"

	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/event/decoder"
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
	ProcEventor     *Eventor
}

type Eventor struct {
	Config        *config.Config
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
	Writer        *dbwriter.EventWriter
}

func NewEvent(config *config.Config, resourceEventQueue *queue.OverwriteQueue, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*Event, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_EVENT_QUEUE)
	eventWriter, err := dbwriter.NewEventWriter(config)
	if err != nil {
		return nil, err
	}
	resourceEventor, err := NewResouceEventor(resourceEventQueue, common.RESOURCE_EVENT, eventWriter, config)
	if err != nil {
		return nil, err
	}
	procEventor, err := NewEventor(config, recv, manager, platformDataManager, eventWriter)
	if err != nil {
		return nil, err
	}
	return &Event{
		Config:          config,
		ResourceEventor: resourceEventor,
		ProcEventor:     procEventor,
	}, nil
}

func NewResouceEventor(eventQueue *queue.OverwriteQueue, eventType common.EventType, eventWriter *dbwriter.EventWriter, config *config.Config) (*Eventor, error) {
	d := decoder.NewDecoder(
		eventType,
		queue.QueueReader(eventQueue),
		eventWriter,
		nil,
		config,
	)
	return &Eventor{
		Config:   config,
		Decoders: []*decoder.Decoder{d},
		Writer:   eventWriter,
	}, nil
}

func NewEventor(config *config.Config, recv *receiver.Receiver, manager *dropletqueue.Manager, platformDataManager *grpc.PlatformDataManager, eventWriter *dbwriter.EventWriter) (*Eventor, error) {
	eventMsg := datatype.MESSAGE_TYPE_PROC_EVENT
	queueCount := config.DecoderQueueCount
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+eventMsg.String(),
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(eventMsg, decodeQueues, queueCount)

	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	var err error
	for i := 0; i < queueCount; i++ {
		platformDatas[i], err = platformDataManager.NewPlatformInfoTable(false, "event-"+eventMsg.String()+"-"+strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		decoders[i] = decoder.NewDecoder(
			common.PROC_EVENT,
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			eventWriter,
			platformDatas[i],
			config,
		)
	}
	return &Eventor{
		Config:        config,
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		Writer:        eventWriter,
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
	e.ProcEventor.Start()
}

func (e *Event) Close() error {
	e.ResourceEventor.Start()
	e.ProcEventor.Close()
	return nil
}
