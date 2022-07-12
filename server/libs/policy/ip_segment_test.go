/*
 * Copyright (c) 2022 Yunshan Networks
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

package policy

import (
	"testing"
)

func TestIpSegmentSimple(t *testing.T) {
	ips, _ := newIpSegment("192.168.10.12/23", 0)
	if ips.getMask() != 0xfffffe00 {
		t.Errorf("Error ipsegment 192.168.10.12/23 mask return 0x%x\n", ips.getMask())
	}
	if ips.getIp() != 0xc0a80a00 {
		t.Errorf("Error ipsegment 192.168.10.12/23 ip return 0x%x\n", ips.getIp())
	}

	ips, _ = newIpSegment("0.0.0.0/0", 0)
	if ips.getMask() != 0 {
		t.Errorf("Error ipsegment 0.0.0.0/0 mask return 0x%x\n", ips.getMask())
	}
	if ips.getIp() != 0 {
		t.Errorf("Error ipsegment 0.0.0.0/0 ip return 0x%x\n", ips.getIp())
	}
}

func TestIpSegmentIp6(t *testing.T) {
	ips, _ := newIpSegment("aabb:ccdd::1/32", 10)
	mask0, mask1 := ips.getMask6()
	ip0, ip1 := ips.getIp6()
	if mask0 != 0xffffffff00000000 || mask1 != 0 {
		t.Errorf("Error ipsegment aabb:ccdd::1/32 mask return 0x%x 0x%x\n", mask0, mask1)
	}
	if ip0 != 0xaabbccdd00000000 || ip1 != 0 {
		t.Errorf("Error ipsegment aabb:ccdd::1/32 ip return 0x%x 0x%x\n", ip0, ip1)
	}

	ips, _ = newIpSegment("fe80::20c:29ff:fe15:a3f/126", 20)
	mask0, mask1 = ips.getMask6()
	ip0, ip1 = ips.getIp6()
	if mask0 != 0xffffffffffffffff || mask1 != 0xfffffffffffffffc {
		t.Errorf("Error ipsegment fe80::20c:29ff:fe15:a3f/126 mask return 0x%x 0x%x\n", mask0, mask1)
	}
	if ip0 != 0xfe80000000000000 || ip1 != 0x020c29fffe150a3c {
		t.Errorf("Error ipsegment fe80::20c:29ff:fe15:a3f/126 ip return 0x%x 0x%x\n", ip0, ip1)
	}
}
