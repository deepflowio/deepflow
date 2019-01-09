package geo

import (
	"testing"
)

func TestDecodeItem(t *testing.T) {
	cases := 2
	for _, item := range GEO_ENTRIES {
		if cases == 0 {
			break
		}
		if item.IPStart == 712638464 {
			// {"country":"CHN","region":"\u5929\u6d25","ip_end":712703999,"ip_start":712638464,"isp":"\u7535\u4fe1"}
			if DecodeCountry(item.Country) != "CHN" {
				t.Error("转换国家结果不正确")
			}
			if DecodeRegion(item.Region) != "天津" {
				t.Error("转换省份结果不正确")
			}
			if DecodeISP(item.ISP) != "电信" {
				t.Error("转换运营商结果不正确")
			}
			cases--
		} else if item.IPStart == 1053837312 {
			// {"country":"FLK","ip_end":1053837439,"ip_start":1053837312}
			if DecodeCountry(item.Country) != "FLK" {
				t.Error("转换国家结果不正确")
			}
			if DecodeRegion(item.Region) != "未知" {
				t.Error("转换省份结果不正确")
			}
			if DecodeISP(item.ISP) != "未知" {
				t.Error("转换运营商结果不正确")
			}
			cases--
		}
	}
}
