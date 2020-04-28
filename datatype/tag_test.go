package datatype

import (
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"reflect"
	"testing"
)

func TestTagEncodeAndDecode(t *testing.T) {
	p := new(PolicyData)
	p.AclActions = make([]AclAction, 0, 2)
	p.AclActions = append(p.AclActions, AclAction(0).AddActionFlags(ACTION_PACKET_CAPTURING).AddDirections(FORWARD))
	p.AclId = 10
	p.ActionFlags = ACTION_COMPRESS_HEADER
	t1 := Tag{
		PolicyData: *p,
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
