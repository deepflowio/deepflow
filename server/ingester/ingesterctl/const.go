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

package ingesterctl

import "github.com/deepflowio/deepflow/server/libs/debug"

const (
	DEBUG_LISTEN_IP   = "0.0.0.0"
	DEBUG_LISTEN_PORT = 39527
)

const (
	INGESTERCTL_ADAPTER debug.ModuleId = iota
	INGESTERCTL_QUEUE
	INGESTERCTL_LABELER
	INGESTERCTL_RPC
	INGESTERCTL_LOGLEVEL
	INGESTERCTL_CONFIG
	INGESTERCTL_FLOW_METRICS_QUEUE
	INGESTERCTL_FLOW_LOG_QUEUE
	INGESTERCTL_EXTMETRICS_QUEUE
	INGESTERCTL_PCAP_QUEUE

	INGESTERCTL_MAX
)

const (
	DEBUG_MESSAGE_LEN = 4096
)

var ConfigPath string
