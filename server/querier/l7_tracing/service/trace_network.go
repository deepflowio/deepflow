/*
 * Copyright (c) 2023 Yunshan Networks
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

package service

import (
	"math"

	"github.com/deepflowio/deepflow/server/querier/l7_tracing/common"
	"github.com/deepflowio/deepflow/server/querier/l7_tracing/model"
	"golang.org/x/exp/slices"
)

type Network struct {
	TraceNetwork *model.TraceNetwork
}

func (n Network) AddFlow(flow *model.L7TracingSpan, NetworkDelayUs int) bool {
	if len(n.TraceNetwork.Flows) > 0 {
		if n.TraceNetwork.ReqTcpSeq != 0 && flow.Type != common.L7_FLOW_TYPE_RESPONSE && n.TraceNetwork.ReqTcpSeq != flow.ReqTcpSeq {
			return false
		}
		if n.TraceNetwork.RespTcpSeq != 0 && flow.Type != common.L7_FLOW_TYPE_REQUEST && n.TraceNetwork.RespTcpSeq != flow.RespTcpSeq {
			return false
		}
		if flow.Type == common.L7_FLOW_TYPE_RESPONSE || n.TraceNetwork.ReqTcpSeq == 0 {
			if n.TraceNetwork.HttpProxyClient != "" && n.TraceNetwork.HttpProxyClient != flow.HttpProxyClient {
				return false
			}
		} else if flow.Type == common.L7_FLOW_TYPE_REQUEST || n.TraceNetwork.RespTcpSeq == 0 {
			if n.TraceNetwork.Protocol != 0 && n.TraceNetwork.Protocol != flow.Protocol {
				return false
			}
			if n.TraceNetwork.L7Protocol != 0 && n.TraceNetwork.L7Protocol != flow.L7Protocol {
				if !slices.Contains[int]([]int{21, 41}, n.TraceNetwork.L7Protocol) || !slices.Contains[int]([]int{21, 41}, flow.L7Protocol) {
					return false
				}
			}
			if n.TraceNetwork.L7ProtocolStr != "" && n.TraceNetwork.L7ProtocolStr != flow.L7ProtocolStr {
				// http2 == grpc
				if !slices.Contains[string]([]string{"HTTP2", "gRPC"}, n.TraceNetwork.L7ProtocolStr) || !slices.Contains[string]([]string{"HTTP2", "gRPC"}, flow.L7ProtocolStr) {
					return false
				}
			}
			if n.TraceNetwork.Version != "" && n.TraceNetwork.Version != flow.Version {
				return false
			}
			if n.TraceNetwork.TraceID != "" && n.TraceNetwork.TraceID != flow.TraceID {
				return false
			}
			if n.TraceNetwork.SpanID != "" && n.TraceNetwork.SpanID != flow.SpanID {
				return false
			}
			if n.TraceNetwork.Endpoint != "" && n.TraceNetwork.Endpoint != flow.Endpoint {
				return false
			}
		} else {
			if n.TraceNetwork.Protocol != 0 && n.TraceNetwork.Protocol != flow.Protocol {
				return false
			}
			if n.TraceNetwork.L7Protocol != 0 && n.TraceNetwork.L7Protocol != flow.L7Protocol {
				if !slices.Contains[int]([]int{21, 41}, n.TraceNetwork.L7Protocol) || !slices.Contains[int]([]int{21, 41}, flow.L7Protocol) {
					return false
				}
			}
			if n.TraceNetwork.L7ProtocolStr != "" && n.TraceNetwork.L7ProtocolStr != flow.L7ProtocolStr {
				// http2 == grpc
				if !slices.Contains[string]([]string{"HTTP2", "gRPC"}, n.TraceNetwork.L7ProtocolStr) || !slices.Contains[string]([]string{"HTTP2", "gRPC"}, flow.L7ProtocolStr) {
					return false
				}
			}
			if n.TraceNetwork.Version != "" && n.TraceNetwork.Version != flow.Version {
				return false
			}
			if n.TraceNetwork.TraceID != "" && n.TraceNetwork.TraceID != flow.TraceID {
				return false
			}
			if n.TraceNetwork.SpanID != "" && n.TraceNetwork.SpanID != flow.SpanID {
				return false
			}
			if n.TraceNetwork.Endpoint != "" && n.TraceNetwork.Endpoint != flow.Endpoint {
				return false
			}
			if n.TraceNetwork.HttpProxyClient != "" && n.TraceNetwork.HttpProxyClient != flow.HttpProxyClient {
				return false
			}
		}
		if n.TraceNetwork.XRequestID0 != "" && n.TraceNetwork.XRequestID0 != flow.XRequestID0 {
			return false
		}
		if n.TraceNetwork.XRequestID1 != "" && n.TraceNetwork.XRequestID1 != flow.XRequestID1 {
			return false
		}

		absStartTimeUs := math.Abs(float64(n.TraceNetwork.StartTimeUs - flow.StartTimeUs))
		absEndTimeUs := math.Abs(float64(n.TraceNetwork.EndTimeUs - flow.EndTimeUs))
		if absStartTimeUs > float64(NetworkDelayUs) || absEndTimeUs > float64(NetworkDelayUs) {
			return false
		}
	}

	if n.TraceNetwork.ReqTcpSeq == 0 && flow.ReqTcpSeq != 0 {
		n.TraceNetwork.ReqTcpSeq = flow.ReqTcpSeq
	}
	if n.TraceNetwork.RespTcpSeq == 0 && flow.RespTcpSeq != 0 {
		n.TraceNetwork.RespTcpSeq = flow.RespTcpSeq
	}
	if n.TraceNetwork.Protocol == 0 && flow.Protocol != 0 {
		n.TraceNetwork.Meta.Protocol = flow.Protocol
	}
	if n.TraceNetwork.L7Protocol == 0 && flow.L7Protocol != 0 {
		n.TraceNetwork.Meta.L7Protocol = flow.L7Protocol
	}
	if n.TraceNetwork.L7ProtocolStr == "" && flow.L7ProtocolStr != "" {
		n.TraceNetwork.Meta.L7ProtocolStr = flow.L7ProtocolStr
	}
	if n.TraceNetwork.Version == "" && flow.Version != "" {
		n.TraceNetwork.Meta.Version = flow.Version
	}
	if n.TraceNetwork.TraceID == "" && flow.TraceID != "" {
		n.TraceNetwork.Meta.TraceID = flow.TraceID
	}
	if n.TraceNetwork.SpanID == "" && flow.SpanID != "" {
		n.TraceNetwork.Meta.SpanID = flow.SpanID
		n.TraceNetwork.SpanID = flow.SpanID
	}
	if n.TraceNetwork.Endpoint == "" && flow.Endpoint != "" {
		n.TraceNetwork.Meta.Endpoint = flow.Endpoint
	}
	if n.TraceNetwork.HttpProxyClient == "" && flow.HttpProxyClient != "" {
		n.TraceNetwork.Meta.HttpProxyClient = flow.HttpProxyClient
	}
	if n.TraceNetwork.XRequestID0 == "" && flow.XRequestID0 != "" {
		n.TraceNetwork.Meta.XRequestID0 = flow.XRequestID0
	}
	if n.TraceNetwork.XRequestID1 == "" && flow.XRequestID1 != "" {
		n.TraceNetwork.Meta.XRequestID1 = flow.XRequestID1
	}
	if n.TraceNetwork.StartTimeUs == 0 {
		n.TraceNetwork.StartTimeUs = flow.StartTimeUs
	}
	if n.TraceNetwork.EndTimeUs == 0 {
		n.TraceNetwork.EndTimeUs = flow.EndTimeUs
	}

	n.TraceNetwork.Flows = append(n.TraceNetwork.Flows, flow)
	if slices.Contains[string]([]string{common.TAP_SIDE_SERVER_PROCESS, common.TAP_SIDE_CLIENT_PROCESS}, flow.TapSide) {
		n.TraceNetwork.HasSyscall = true
		flow.Network = n.TraceNetwork
	}
	return true
}

func (n Network) SortAndSetParent() {
	n.TraceNetwork.Flows = common.NetworkFlowSort(n.TraceNetwork.Flows)
	for i := len(n.TraceNetwork.Flows) - 1; i >= 0; i-- {
		if i-1 >= 0 {
			common.SetParent(n.TraceNetwork.Flows[i], n.TraceNetwork.Flows[i-1], "trace mounted due to tcp_seq")
		}
	}
}
