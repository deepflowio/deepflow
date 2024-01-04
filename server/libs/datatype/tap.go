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

package datatype

// TAP: Traffic Access Point
//
// Indicates the flow data collection location.  Currently supports 256
// acquisition locations. The traffic in cloud is uniformly represented by
// a special value `3`, and the other values represent the traffic
// collected from optical splitting and mirroring at different locations
// in the IDC.
//
// Note: For historical reasons, we use the confusing term VTAP to refer
// to deepflow-agent, and vtap_id to represent the id of a deepflow-agent.
type TapType uint16

const (
	TAP_ANY     TapType = 0 // match any TapType
	TAP_IDC_MIN TapType = 1
	TAP_CLOUD   TapType = 3
	TAP_MAX     TapType = 256 // exclusive

	TAP_MIN TapType = TAP_ANY + 1
)
