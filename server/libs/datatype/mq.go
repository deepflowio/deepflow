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

package datatype

import (
	"fmt"
	"strconv"

	"github.com/deepflowio/deepflow/server/libs/datatype/pb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var kafkaInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(KafkaInfo)
})

func AcquireKafkaInfo() *KafkaInfo {
	return kafkaInfoPool.Get().(*KafkaInfo)
}

func ReleaseKafkaInfo(d *KafkaInfo) {
	*d = KafkaInfo{}
	kafkaInfoPool.Put(d)
}

type KafkaInfo struct {
	CorrelationId uint32

	// request
	ReqMsgSize int32
	ApiVersion uint16
	ApiKey     uint16
	ClientID   string

	// reponse
	RespMsgSize int32
}

func (i *KafkaInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	if i.CorrelationId != 0 {
		p.ExtInfo = &pb.ExtendedInfo{
			RequestId: i.CorrelationId,
		}
	}

	p.ReqLen, p.RespLen = -1, -1
	if msgType == MSG_T_REQUEST || msgType == MSG_T_SESSION {
		p.Req = &pb.L7Request{
			ReqType: KafkaCommand(i.ApiKey).String(),
		}
		p.ReqLen = int32(i.ReqMsgSize)
	}

	if msgType == MSG_T_RESPONSE || msgType == MSG_T_SESSION {
		p.RespLen = int32(i.RespMsgSize)
	}
}

func (i *KafkaInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *KafkaInfo) Merge(r interface{}) {
	if kafka, ok := r.(*KafkaInfo); ok {
		i.RespMsgSize = kafka.RespMsgSize
	}
}

var mqttInfoPool = pool.NewLockFreePool(func() interface{} {
	return new(MqttInfo)
})

func AcquireMqttInfo() *MqttInfo {
	return mqttInfoPool.Get().(*MqttInfo)
}

func ReleaseMqttInfo(d *MqttInfo) {
	*d = MqttInfo{}
	mqttInfoPool.Put(d)
}

type MqttInfo struct {
	MqttType string

	// request
	ReqMsgSize   int32
	ProtoVersion uint16
	ClientID     string

	// reponse
	RespMsgSize int32
}

func (i *MqttInfo) WriteToPB(p *pb.AppProtoLogsData, msgType LogMessageType) {
	switch i.ProtoVersion {
	case 3:
		p.Version = "3.1"
	case 4:
		p.Version = "3.1.1"
	case 5:
		p.Version = "5.0"
	default:
		p.Version = strconv.Itoa(int(i.ProtoVersion))
	}

	p.ReqLen, p.RespLen = -1, -1
	if msgType == MSG_T_REQUEST || msgType == MSG_T_SESSION {
		p.Req = &pb.L7Request{
			ReqType: i.MqttType,
			Domain:  i.ClientID,
		}
		p.ReqLen = int32(i.ReqMsgSize)
	}

	if msgType == MSG_T_RESPONSE || msgType == MSG_T_SESSION {
		p.RespLen = int32(i.RespMsgSize)
	}
}

func (i *MqttInfo) String() string {
	return fmt.Sprintf("%#v", i)
}

func (i *MqttInfo) Merge(r interface{}) {
	if mqtt, ok := r.(*MqttInfo); ok {
		i.RespMsgSize = mqtt.RespMsgSize
	}
}
