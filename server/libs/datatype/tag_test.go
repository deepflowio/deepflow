package datatype

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"reflect"
	"testing"
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
