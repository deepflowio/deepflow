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

package common

const (
	FLOW_LOG_DB = "flow_log"
)

type FlowLogID uint8

const (
	L4_FLOW_ID FlowLogID = iota
	L7_FLOW_ID
	L4_PACKET_ID
	L4_PCAP_FLOW_ID // The flow log with PCAP flag is also written to 'l4_flow_log' table, but it needs to be written and monitored separately

	FLOWLOG_ID_MAX
)

var flowLogNames = []string{
	L4_FLOW_ID:      "l4_flow_log",
	L7_FLOW_ID:      "l7_flow_log",
	L4_PACKET_ID:    "l4_packet",
	L4_PCAP_FLOW_ID: "l4_flow_log",
}

func (l FlowLogID) String() string {
	return flowLogNames[l]
}

func (l FlowLogID) TimeKey() string {
	return "time"
}
