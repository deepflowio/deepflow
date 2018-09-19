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
