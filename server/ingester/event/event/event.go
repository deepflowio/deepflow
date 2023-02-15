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
	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/event/decoder"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Event struct {
	Config        *config.Config
	ResourceEvent *Eventor
}

type Eventor struct {
	Config  *config.Config
	Decoder *decoder.Decoder
	Writer  *dbwriter.EventWriter
}

func NewEvent(config *config.Config, resourceEventQueue *queue.OverwriteQueue) (*Event, error) {
	resourceEvent, err := NewEventor(resourceEventQueue, common.RESOURCE_EVENT, config)
	if err != nil {
		return nil, err
	}
	return &Event{
		Config:        config,
		ResourceEvent: resourceEvent,
	}, nil
}

func NewEventor(eventQueue *queue.OverwriteQueue, eventType common.EventType, config *config.Config) (*Eventor, error) {
	eventWriter, err := dbwriter.NewEventWriter(eventType, config)
	if err != nil {
		return nil, err
	}
	decoder := decoder.NewDecoder(
		eventType,
		queue.QueueReader(eventQueue),
		eventWriter,
		config,
	)
	return &Eventor{
		Config:  config,
		Decoder: decoder,
		Writer:  eventWriter,
	}, nil
}

func (e *Eventor) Start() {
	go e.Decoder.Run()
}

func (e *Eventor) Close() {
	e.Decoder.Close()
}

func (e *Event) Start() {
	e.ResourceEvent.Start()
}

func (e *Event) Close() error {
	e.ResourceEvent.Close()
	return nil
}
