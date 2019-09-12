package datatype

import (
	"reflect"
	"testing"
)

func newMatchedField(tap TapType, vlan uint32, proto uint8, srcMac, dstMac uint64, srcIp, dstIp uint32, srcPort, dstPort uint16) MatchedField {
	matched := MatchedField{}
	matched.Set(MATCHED_TAP_TYPE, uint64(tap))
	matched.Set(MATCHED_PROTO, uint64(proto))
	matched.Set(MATCHED_VLAN, uint64(vlan))
	matched.Set(MATCHED_SRC_MAC, srcMac)
	matched.Set(MATCHED_DST_MAC, dstMac)
	matched.Set(MATCHED_SRC_IP, uint64(srcIp))
	matched.Set(MATCHED_DST_IP, uint64(dstIp))
	matched.Set(MATCHED_SRC_PORT, uint64(srcPort))
	matched.Set(MATCHED_DST_PORT, uint64(dstPort))
	return matched
}

func TestSetGet1(t *testing.T) {
	matched := newMatchedField(1, 2, 3, 10, 30, 20, 40, 50, 60)
	if matched.Get(MATCHED_TAP_TYPE) != 1 {
		t.Errorf("MATCHED_TAP_TYPE Error. %v\n", matched)
	}
	if matched.Get(MATCHED_VLAN) != 2 {
		t.Errorf("MATCHED_VLAN Error. %s\n", matched)
	}
	if matched.Get(MATCHED_PROTO) != 3 {
		t.Errorf("MATCHED_PROTO Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_MAC) != 10 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_IP) != 20 {
		t.Errorf("MATCHED_SRC_IP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_PORT) != 50 {
		t.Errorf("MATCHED_SRC_PORT Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_MAC) != 30 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_IP) != 40 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_PORT) != 60 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
}

func TestSetGet2(t *testing.T) {
	matched := newMatchedField(0x3f, 0x1fff, 0x7, 10, 30, 20, 40, 50, 60)
	if matched.Get(MATCHED_TAP_TYPE) != 0x1f {
		t.Errorf("MATCHED_TAP_TYPE Error. %v\n", matched)
	}
	if matched.Get(MATCHED_VLAN) != 0xfff {
		t.Errorf("MATCHED_VLAN Error. %s\n", matched)
	}
	if matched.Get(MATCHED_PROTO) != 0x7 {
		t.Errorf("MATCHED_PROTO Error. %s\n", matched)
	}
}

func TestBitZero(t *testing.T) {
	matched := newMatchedField(1, 1, 1, 1, 1, 0, 1, 1, 0)
	if matched.IsBitZero(0) != false {
		t.Errorf("0 bits Error. %s\n", matched)
	}
	if matched.IsBitZero(128) != true {
		t.Errorf("1 bits Error. %s\n", matched)
	}
}

func TestTableIndex(t *testing.T) {
	matched := newMatchedField(1, 1, 1, 1, 1, 1, 1, 0, 0)
	maskVector := newMatchedField(1, 0, 1, 0, 0, 0, 0, 0, 0)
	index := matched.GetTableIndex(&maskVector, 217, 249)
	if index != 0x3 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x3.")
		t.Errorf("Actual index: %d.\n", index)
	}

	matched = newMatchedField(1, 0, 1, 1, 1, 1, 1, 0, 0)
	maskVector = newMatchedField(1, 1, 1, 0, 0, 0, 0, 0, 0)
	index = matched.GetTableIndex(&maskVector, 217, 249)
	if index != 0x5 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x5.")
		t.Errorf("Actual index: %d.\n", index)
	}

	matched = newMatchedField(1, 1, 1, 1, 1, 1, 1, 1, 1)
	maskVector = newMatchedField(0, 0, 0, 0, 0, 0, 1, 1, 1)
	index = matched.GetTableIndex(&maskVector, 0, 160)
	if index != 0x7 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x7.")
		t.Errorf("Actual index: %d.\n", index)
	}
}

func TestMatchedFieldGetAllTableIndex(t *testing.T) {
	// 若matched为0101， vector为0111, mask为1001，返回{001,011,101,111}
	matched := newMatchedField(1, 2, 3, 10, 30, 20, 40, 5, 60)
	vector := newMatchedField(0, 0, 0, 0, 0, 0, 0, 7, 0)
	mask := newMatchedField(0, 0, 0, 0, 0, 0, 0, 9, 0)
	indexs := matched.GetAllTableIndex(&vector, &mask, 48, 64, []int{48, 49, 50})
	if !reflect.DeepEqual([]uint16{1, 3, 5, 7}, indexs) {
		t.Errorf("TestMatchedFieldGetAllTableIndex Error. %+v\n", indexs)
	}
}
