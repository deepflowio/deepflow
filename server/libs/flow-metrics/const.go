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

import logging "github.com/op/go-logging"

var log = logging.MustGetLogger("flow_metrics")

const (
	MAX_STRING_LENGTH = 2048
)

const (
	FLOW_SECOND_ID uint8 = iota
	FLOW_ID
	_      // GEO_ID，已删除
	_      // PACKET_ID，已删除
	ACL_ID // 目前meter的ACL_ID和PACKET_ID内容一致
	APP_ID

	MAX_APP_ID
)

var MeterVTAPNames [MAX_APP_ID]string = [MAX_APP_ID]string{
	"vtap_flow",
	"vtap_flow",
	"vtap_wan",
	"vtap_packet",
	"vtap_acl",
	"vtap_app",
}

var MeterNamesToID map[string]uint8

func GetMeterID(name string) uint8 {
	// TODO: fix this: cannot produce FLOW_ID from "vtap_flow"
	if id, exist := MeterNamesToID[name]; exist {
		return id
	}
	log.Errorf("can't get meter(%s) id", name)
	return MAX_APP_ID
}

const (
	MAIN uint8 = iota

	MAX_MEASUREMENT_ID
)

var MeasurementNames [MAX_MEASUREMENT_ID]string = [MAX_MEASUREMENT_ID]string{
	"main",
}

var MeasurementNamesToID map[string]uint8

func GetMeasurementID(name string) uint8 {
	if mid, exist := MeasurementNamesToID[name]; exist {
		return mid
	}
	log.Errorf("can't get measurement(%s) id", name)
	return MAX_MEASUREMENT_ID
}

func init() {
	MeterNamesToID = make(map[string]uint8)
	for id, name := range MeterVTAPNames {
		MeterNamesToID[name] = uint8(id)
	}

	MeasurementNamesToID = make(map[string]uint8)
	for id, name := range MeasurementNames {
		MeasurementNamesToID[name] = uint8(id)
	}
}
