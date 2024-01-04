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

import (
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/libs/codec"
)

func TestTagEncodeAndDecode(t *testing.T) {
	p := new(PolicyData)
	action := ToNpbActions(10, 100, NPB_TUNNEL_TYPE_PCAP, 0, 0)
	p.NpbActions = make([]NpbActions, 0, 2)
	p.NpbActions = append(p.NpbActions, action)
	p.AclId = 10
	p.ActionFlags = ACTION_PCAP
	t1 := Tag{
		PolicyData: [2]PolicyData{*p, *p},
	}
	t2 := Tag{}
	e := codec.SimpleEncoder{}
	d := codec.SimpleDecoder{}

	t1.Encode(&e)
	d.Init(e.Bytes())
	t2.Decode(&d)
	t.Logf("t1 :%v, t2 :%v", t1, t2)
	if reflect.DeepEqual(t1, t2) == false {
		t.Errorf("编解码函数实现错误")
	}
}
