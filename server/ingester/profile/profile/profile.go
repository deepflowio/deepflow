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

package profile

import (
	"strconv"
	"time"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/profile/config"
	"github.com/deepflowio/deepflow/server/ingester/profile/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/profile/decoder"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

type Profile struct {
	Profiler *Profiler
}

type Profiler struct {
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
}

func NewProfile(config *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*Profile, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_PROFILE_QUEUE)
	profiler, err := NewProfiler(datatype.MESSAGE_TYPE_PROFILE, config, platformDataManager, manager, recv)
	if err != nil {
		return nil, err
	}
	return &Profile{
		Profiler: profiler,
	}, nil
}

func NewProfiler(msgType datatype.MessageType, config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver) (*Profiler, error) {
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+msgType.String(),
		config.DecoderQueueSize,
		config.DecoderQueueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(msgType, decodeQueues, config.DecoderQueueCount)
	decoders := make([]*decoder.Decoder, config.DecoderQueueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, config.DecoderQueueCount)
	for i := 0; i < config.DecoderQueueCount; i++ {
		if platformDataManager != nil {
			var err error
			platformDatas[i], err = platformDataManager.NewPlatformInfoTable("profile-" + msgType.String() + "-" + strconv.Itoa(i))
			if err != nil {
				return nil, err
			}
			debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_PROFILE, platformDatas[i])
		}
		profileWriter, err := dbwriter.NewProfileWriter(datatype.MESSAGE_TYPE_PROFILE, i, config)
		if err != nil {
			return nil, err
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			*config.CompressionAlgorithm,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			profileWriter,
		)
	}
	return &Profiler{
		Decoders:      decoders,
		PlatformDatas: platformDatas,
	}, nil
}

func (p *Profiler) Start() {
	for _, platformData := range p.PlatformDatas {
		if platformData != nil {
			platformData.Start()
		}
	}

	for _, decoder := range p.Decoders {
		if decoder != nil {
			go decoder.Run()
		}
	}
}

func (p *Profiler) Close() {
	for _, platformData := range p.PlatformDatas {
		if platformData != nil {
			platformData.ClosePlatformInfoTable()
		}
	}

	for _, decoder := range p.Decoders {
		if decoder != nil {
			decoder.Close()
		}
	}
}

func (p *Profile) Start() {
	p.Profiler.Start()
}

func (p *Profile) Close() error {
	p.Profiler.Close()
	return nil
}
