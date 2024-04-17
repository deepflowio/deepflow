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

package common

import (
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("common")

type EventType uint8

const (
	RESOURCE_EVENT EventType = iota
	PERF_EVENT
	ALARM_EVENT
	K8S_EVENT
)

func (e EventType) String() string {
	switch e {
	case RESOURCE_EVENT:
		return "resource_event"
	case PERF_EVENT:
		return "perf_event"
	case ALARM_EVENT:
		return "alarm_event"
	case K8S_EVENT:
		return "k8s_event"
	default:
		return "unknown_event"
	}
}

func (e EventType) TableName() string {
	switch e {
	// both resource_event and k8s_event are stored in event table
	case RESOURCE_EVENT, K8S_EVENT:
		return "event"
	case PERF_EVENT:
		return "perf_event"
	case ALARM_EVENT:
		return "alarm_event"
	default:
		return "unknown_event"
	}
}
