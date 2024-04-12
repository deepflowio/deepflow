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

package flow_metrics

import (
	"testing"
)

func TestMarshalFlowMeter(t *testing.T) {
	var buffer [1024]byte
	var l int

	m1 := FlowMeter{
		Traffic: Traffic{
			PacketTx:   1,
			PacketRx:   2,
			ByteTx:     3,
			ByteRx:     4,
			NewFlow:    6,
			ClosedFlow: 7,
		},
	}
	l = m1.MarshalTo(buffer[:])
	if string(buffer[:l]) != "packet=3i,packet_tx=1i,packet_rx=2i,byte_tx=3i,byte_rx=4i,byte=7i,new_flow=6i,closed_flow=7i" {
		t.Error("MarshalTo()实现不正确")
	}

	m2 := FlowMeter{
		Latency: Latency{
			RTTClientSum:   uint64(1000),
			RTTClientCount: 2,
		},
	}
	l = m2.MarshalTo(buffer[:])
	if string(buffer[:l]) != "packet=0i,rtt_client_sum=1000i,rtt_client_count=2i" {
		t.Error("MarshalTo()实现不正确")
	}

	m3 := FlowMeter{
		Traffic: Traffic{
			PacketTx:   1,
			PacketRx:   2,
			ByteTx:     3,
			ByteRx:     4,
			NewFlow:    6,
			ClosedFlow: 7,
		},
		Anomaly: Anomaly{
			ClientRstFlow: 1,
			ClientAckMiss: 1,
		},
	}
	l = m3.MarshalTo(buffer[:])
	expected := "packet=3i,packet_tx=1i,packet_rx=2i,byte_tx=3i,byte_rx=4i,byte=7i,new_flow=6i,closed_flow=7i,client_rst_flow=1i,client_ack_miss=1i,server_establish_fail=1i,tcp_establish_fail=1i"
	if string(buffer[:l]) != expected {
		t.Error("MarshalTo()实现不正确", "\nactual is:", string(buffer[:l]), "\nexpected is:", expected)
	}
}

func TestFlowMeterRelease(t *testing.T) {
	m1 := FlowMeter{
		Traffic: Traffic{
			PacketTx:   1,
			PacketRx:   2,
			ByteTx:     3,
			ByteRx:     4,
			NewFlow:    6,
			ClosedFlow: 7,
		},
	}
	m1.Release()
	m2 := FlowMeter{}
	if m1 != m2 {
		t.Error("Release()实现不正确")
	}
}

func TestFlowMeterClone(t *testing.T) {
	m1 := FlowMeter{
		Traffic: Traffic{
			PacketTx:   1,
			PacketRx:   2,
			ByteTx:     3,
			ByteRx:     4,
			NewFlow:    6,
			ClosedFlow: 7,
		},
	}

	m2 := CloneFlowMeter(&m1)

	if *m2 != m1 {
		t.Error("CloneFlowMeter()实现不正确")
	}
}
