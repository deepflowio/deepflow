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
	exportconfig "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("common")

type EventType uint8

const (
	RESOURCE_EVENT EventType = iota
	FILE_EVENT
	FILE_AGG_EVENT
	FILE_MGMT_EVENT
	PROC_PERM_EVENT
	PROC_OPS_EVENT
	ALERT_EVENT
	K8S_EVENT
	ALERT_RECORD
)

func (e EventType) String() string {
	switch e {
	case RESOURCE_EVENT:
		return "resource_event"
	case FILE_EVENT:
		return "file_event"
	case FILE_AGG_EVENT:
		return "file_agg_event"
	case FILE_MGMT_EVENT:
		return "file_mgmt_event"
	case PROC_PERM_EVENT:
		return "proc_perm_event"
	case PROC_OPS_EVENT:
		return "proc_ops_event"
	case ALERT_EVENT:
		return "alert_event"
	case K8S_EVENT:
		return "k8s_event"
	case ALERT_RECORD:
		return "alert_record"
	default:
		return "unknown_event"
	}
}

func (e EventType) TableName() string {
	switch e {
	// both resource_event and k8s_event are stored in event table
	case RESOURCE_EVENT, K8S_EVENT:
		return "event"
	case FILE_EVENT:
		return "file_event"
	case FILE_AGG_EVENT:
		return "file_agg_event"
	case FILE_MGMT_EVENT:
		return "file_mgmt_event"
	case PROC_PERM_EVENT:
		return "proc_perm_event"
	case PROC_OPS_EVENT:
		return "proc_ops_event"
	case ALERT_EVENT:
		return "alert_event"
	case ALERT_RECORD:
		return "alert_record"
	default:
		return "unknown_event"
	}
}

func (e EventType) DataSource() uint32 {
	switch e {
	case FILE_EVENT, FILE_AGG_EVENT, FILE_MGMT_EVENT, PROC_PERM_EVENT, PROC_OPS_EVENT:
		return uint32(exportconfig.FILE_EVENT)
	default:
		return uint32(exportconfig.MAX_DATASOURCE_ID)
	}
}
