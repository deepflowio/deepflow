package geo

func DecodeCountry(country uint8) string {
	return decode(COUNTRY_NAMES[:], country)
}

func DecodeRegion(region uint8) string {
	return decode(REGION_NAMES[:], region)
}

func DecodeISP(isp uint8) string {
	return decode(ISP_NAMES[:], isp)
}

func decode(list []string, key uint8) string {
	if int(key) >= len(list) {
		return "未知"
	}
	return list[key]
}
