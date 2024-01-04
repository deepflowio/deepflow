/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package geo

import (
	tree "github.com/deepflowio/deepflow/server/libs/segmenttree"
)

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

func EncodeCountry(country string) uint8 {
	if v, ok := COUNTRY_NAMES_MAP[country]; ok {
		return v
	}
	return 0
}

func EncodeRegion(region string) uint8 {
	if v, ok := REGION_NAMES_MAP[region]; ok {
		return v
	}
	return 0
}

func EncodeISP(isp string) uint8 {
	if v, ok := ISP_NAMES_MAP[isp]; ok {
		return v
	}
	return 0
}

type IPRange struct {
	lower uint32
	upper uint32
}

func newIPPoint(ip uint32) *IPRange {
	return &IPRange{ip, ip}
}

func newIPRange(lower, upper uint32) *IPRange {
	return &IPRange{lower, upper}
}

func (r *IPRange) Lower() (endpoint tree.Endpoint, closed bool) {
	return int64(r.lower), true
}

func (r *IPRange) Upper() (endpoint tree.Endpoint, closed bool) {
	return int64(r.upper), true
}
