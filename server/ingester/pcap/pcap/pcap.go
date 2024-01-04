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

package pcap

import (
	"time"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/pcap/config"
	"github.com/deepflowio/deepflow/server/ingester/pcap/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/pcap/decoder"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

type Pcaper struct {
	Config   *config.Config
	Decoders []*decoder.Decoder
	Writer   *dbwriter.PcapWriter
}

func NewPcaper(recv *receiver.Receiver, config *config.Config) (*Pcaper, error) {
	msgType := datatype.MESSAGE_TYPE_RAW_PCAP
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_PCAP_QUEUE)
	queueCount := config.PcapQueueCount
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+datatype.MessageTypeString[int(msgType)],
		config.PcapQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(msgType, decodeQueues, queueCount)

	pcapWriter, err := dbwriter.NewPcapWriter(config)
	if err != nil {
		return nil, err
	}

	decoders := make([]*decoder.Decoder, queueCount)
	for i := 0; i < queueCount; i++ {
		decoders[i] = decoder.NewDecoder(
			i,
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			pcapWriter,
			config,
		)
	}
	return &Pcaper{
		Config:   config,
		Decoders: decoders,
		Writer:   pcapWriter,
	}, nil
}

func (e *Pcaper) Start() {
	for _, decoder := range e.Decoders {
		go decoder.Run()
	}
}

func (e *Pcaper) Close() error {
	for _, decoder := range e.Decoders {
		decoder.Close()
	}
	return nil
}
