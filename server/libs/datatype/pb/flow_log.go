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

package pb

import (
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var pbAppProtoLogsDataPool = pool.NewLockFreePool(func() interface{} {
	return &AppProtoLogsData{
		Base: &AppProtoLogsBaseInfo{
			Head: &AppProtoHead{},
		},
	}
})

func AcquirePbAppProtoLogsData() *AppProtoLogsData {
	d := pbAppProtoLogsDataPool.Get().(*AppProtoLogsData)
	return d
}

func ReleasePbAppProtoLogsData(d *AppProtoLogsData) {
	if d == nil {
		return
	}

	head := d.Base.Head
	head.Reset()
	basicInfo := d.Base
	basicInfo.Reset()
	basicInfo.Head = head

	req := d.Req
	resp := d.Resp
	traceInfo := d.TraceInfo
	extInfo := d.ExtInfo

	d.Reset()
	d.Base = basicInfo

	if req != nil {
		req.Reset()
		d.Req = req
	}

	if resp != nil {
		resp.Reset()
		d.Resp = resp
	}

	if traceInfo != nil {
		traceInfo.Reset()
		d.TraceInfo = traceInfo
	}

	if extInfo != nil {
		extInfo.Reset()
		d.ExtInfo = extInfo
	}

	pbAppProtoLogsDataPool.Put(d)
}

func (d *AppProtoLogsData) Release() {
	ReleasePbAppProtoLogsData(d)
}

func (d *AppProtoLogsData) IsValid() bool {
	if d == nil ||
		d.Base == nil ||
		d.Base.Head == nil {
		return false
	}
	return true
}

func (t *TaggedFlow) IsValid() bool {
	if t == nil ||
		t.Flow == nil ||
		t.Flow.FlowKey == nil ||
		t.Flow.MetricsPeerSrc == nil ||
		t.Flow.MetricsPeerDst == nil ||
		t.Flow.Tunnel == nil {
		return false
	}
	return true
}

func NewTaggedFlow() *TaggedFlow {
	return &TaggedFlow{
		Flow: &Flow{
			FlowKey:        &FlowKey{},
			MetricsPeerSrc: &FlowMetricsPeer{},
			MetricsPeerDst: &FlowMetricsPeer{},
			Tunnel:         &TunnelField{},
			PerfStats: &FlowPerfStats{
				Tcp: &TCPPerfStats{
					CountsPeerTx: &TcpPerfCountsPeer{},
					CountsPeerRx: &TcpPerfCountsPeer{},
				},
				L7: &L7PerfStats{},
			},
		},
	}
}

// 清空pb的TaggedFlow 使解码时可以反复使用
func (t *TaggedFlow) ResetAll() {
	flowPerfStats := t.Flow.PerfStats
	if flowPerfStats != nil {
		tcpPerfStats := flowPerfStats.Tcp
		tcpPerfCountsPeerTx := tcpPerfStats.CountsPeerTx
		tcpPerfCountsPeerRx := tcpPerfStats.CountsPeerRx

		tcpPerfCountsPeerTx.Reset()
		tcpPerfCountsPeerRx.Reset()
		tcpPerfStats.Reset()
		tcpPerfStats.CountsPeerTx = tcpPerfCountsPeerTx
		tcpPerfStats.CountsPeerRx = tcpPerfCountsPeerRx

		l7PerfStats := flowPerfStats.L7
		l7PerfStats.Reset()

		flowPerfStats.Reset()
		flowPerfStats.L7 = l7PerfStats
		flowPerfStats.Tcp = tcpPerfStats
	}

	flowKey := t.Flow.FlowKey
	flowKey.Reset()
	flowMetricsPeerSrc := t.Flow.MetricsPeerSrc
	flowMetricsPeerSrc.Reset()
	flowMetricsPeerDst := t.Flow.MetricsPeerDst
	flowMetricsPeerDst.Reset()
	tunnel := t.Flow.Tunnel
	tunnel.Reset()

	flow := t.Flow
	flow.Reset()

	if flowPerfStats != nil {
		flow.PerfStats = flowPerfStats
	}
	flow.FlowKey = flowKey
	flow.MetricsPeerSrc = flowMetricsPeerSrc
	flow.MetricsPeerDst = flowMetricsPeerDst
	flow.Tunnel = tunnel

	t.Reset()
	t.Flow = flow
}
