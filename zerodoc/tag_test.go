package zerodoc

import (
	"testing"
)

func TestCustomTag(t *testing.T) {
	f := Field{}
	f.AddCustomField(Country, "country", "CHN")
	s := f.NewTag(Country).ToKVString()
	if s != ",country=CHN" {
		t.Error("自定义Tag处理不正确")
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
