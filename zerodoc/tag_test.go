package zerodoc

import (
	"testing"
)

func TestCustomTag(t *testing.T) {
	f := Field{}
	f.AddCustomField(Country, "country", "CHN")
	dict := f.NewTag(Country).ToMap()
	if dict["country"] != "CHN" {
		t.Error("自定义Tag处理不正确")
	}
}
