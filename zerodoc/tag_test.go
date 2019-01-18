package zerodoc

import (
	"testing"
)

func TestHasEdgeTagField(t *testing.T) {
	c := IPPath
	if !c.HasEdgeTagField() {
		t.Error("Edge Tag处理不正确")
	}
	c = IP
	if c.HasEdgeTagField() {
		t.Error("Edge Tag处理不正确")
	}
}

func TestFillTag(t *testing.T) {
	f := Field{L3EpcID: 3}
	tag := &Tag{}
	f.FillTag(L3EpcID, tag)
	if tag.ToKVString() != ",l3_epc_id=3" {
		t.Error("FillTag处理不正确")
	}
}

func TestFastOrNormalID(t *testing.T) {
	f := Field{L3EpcID: 3, TAPType: ToR, L2EpcID: 2}
	if f.NewTag(L3EpcID|TAPType).GetFastID() == 0 {
		t.Error("FastID没有正确设置")
	}
	if f.NewTag(L3EpcID|L2EpcID).GetFastID() != 0 {
		t.Error("非FastID的Tag被设置了")
	}
}

func TestNegativeID(t *testing.T) {
	a := int16(30000)
	f := Field{L3EpcID: -1, L2EpcID: int16(a * 2), GroupID: -1}
	if f.NewTag(L3EpcID|L2EpcID|GroupID).ToKVString() != ",group_id=-1,l2_epc_id=60000,l3_epc_id=-1" {
		t.Error("int16值处理得不正确")
	}
}
