package datatype

import (
	"testing"
)

func newMatchedField(tap TapType, vlan uint32, proto uint8, srcGroup, dstGroup uint16, srcPort, dstPort uint16) MatchedField {
	matched := MatchedField{}
	matched.Set(MATCHED_TAP_TYPE, uint16(tap))
	matched.Set(MATCHED_PROTO, uint16(proto))
	matched.Set(MATCHED_VLAN, uint16(vlan))
	matched.Set(MATCHED_SRC_GROUP, srcGroup)
	matched.Set(MATCHED_DST_GROUP, dstGroup)
	matched.Set(MATCHED_SRC_PORT, srcPort)
	matched.Set(MATCHED_DST_PORT, dstPort)
	return matched
}

func TestSetGet1(t *testing.T) {
	matched := newMatchedField(1, 2, 3, 10, 20, 30, 40)
	if matched.Get(MATCHED_TAP_TYPE) != 1 {
		t.Errorf("MATCHED_TAP_TYPE Error. %v\n", matched)
	}
	if matched.Get(MATCHED_VLAN) != 2 {
		t.Errorf("MATCHED_VLAN Error. %s\n", matched)
	}
	if matched.Get(MATCHED_PROTO) != 3 {
		t.Errorf("MATCHED_PROTO Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_GROUP) != 10 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_GROUP) != 20 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_PORT) != 30 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_PORT) != 40 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
}

func TestSetGet2(t *testing.T) {
	matched := newMatchedField(0x7, 0x1fff, 0x7, 10, 20, 30, 40)
	if matched.Get(MATCHED_TAP_TYPE) != 3 {
		t.Errorf("MATCHED_TAP_TYPE Error. %v\n", matched)
	}
	if matched.Get(MATCHED_VLAN) != 0xfff {
		t.Errorf("MATCHED_VLAN Error. %s\n", matched)
	}
	if matched.Get(MATCHED_PROTO) != 3 {
		t.Errorf("MATCHED_PROTO Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_GROUP) != 10 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_GROUP) != 20 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_PORT) != 30 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_PORT) != 40 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	matched.Set(MATCHED_SRC_GROUP, 0x1010)
	matched.Set(MATCHED_SRC_GROUP, 0x101)
	if matched.Get(MATCHED_SRC_GROUP) != 0x101 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
}

func TestBitZero(t *testing.T) {
	matched := newMatchedField(1, 1, 1, 1, 1, 1, 1)
	if matched.IsBitZero(0) != false {
		t.Errorf("0 bits Error. %s\n", matched)
	}
	if matched.IsBitZero(1) != true {
		t.Errorf("1 bits Error. %s\n", matched)
	}
}

func TestTableIndex(t *testing.T) {
	matched := newMatchedField(1, 1, 1, 1, 1, 1, 1)
	maskVector := newMatchedField(1, 0, 1, 0, 0, 0, 0)
	index := matched.GetTableIndex(&maskVector, 64, 78)
	if index != 0x3 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x3.")
		t.Errorf("Actual index: %d.\n", index)
	}

	matched = newMatchedField(1, 0, 1, 1, 1, 1, 1)
	maskVector = newMatchedField(1, 1, 1, 0, 0, 0, 0)
	index = matched.GetTableIndex(&maskVector, 64, 78)
	if index != 0x5 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x5.")
		t.Errorf("Actual index: %d.\n", index)
	}

	matched = newMatchedField(1, 1, 1, 1, 1, 1, 1)
	maskVector = newMatchedField(0, 0, 0, 0, 1, 0, 1)
	index = matched.GetTableIndex(&maskVector, 0, 32)
	if index != 0x3 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x3.")
		t.Errorf("Actual index: %d.\n", index)
	}

	matched = newMatchedField(1, 1, 1, 1, 1, 0, 1)
	maskVector = newMatchedField(0, 0, 0, 0, 1, 1, 1)
	index = matched.GetTableIndex(&maskVector, 0, 32)
	if index != 0x5 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x5.")
		t.Errorf("Actual index: %d.\n", index)
	}
}
