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

package log_data

import (
	"encoding/json"
	"testing"

	"github.com/deepflowio/deepflow/server/ingester/flow_log/geo"
	"github.com/deepflowio/deepflow/server/libs/datatype"
)

func TestJsonify(t *testing.T) {
	geo.NewGeoTree()
	info := L4FlowLog{
		DataLinkLayer: DataLinkLayer{
			VLAN: 123,
		},
		FlowInfo: FlowInfo{
			L2End0: true,
		},
	}
	b, _ := json.Marshal(info)
	var newInfo L4FlowLog
	json.Unmarshal(b, &newInfo)
	if info.VLAN != newInfo.VLAN {
		t.Error("string jsonify failed")
	}
	if info.L2End0 != newInfo.L2End0 {
		t.Error("bool jsonify failed")
	}
}

func TestParseUint32EpcID(t *testing.T) {
	if r := parseUint32EpcID(32767); r != 32767 {
		t.Errorf("expect 32767, result %v", r)
	}
	if r := parseUint32EpcID(40000); r != 40000 {
		t.Errorf("expect 40000, result %v", r)
	}
	id := datatype.EPC_FROM_DEEPFLOW
	if r := parseUint32EpcID(uint32(id)); r != datatype.EPC_FROM_DEEPFLOW {
		t.Errorf("expect %v, result %v", datatype.EPC_FROM_DEEPFLOW, r)
	}
	id = datatype.EPC_FROM_INTERNET
	if r := parseUint32EpcID(uint32(id)); r != datatype.EPC_FROM_INTERNET {
		t.Errorf("expect %v, result %v", datatype.EPC_FROM_INTERNET, r)
	}
}
