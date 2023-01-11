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

package utils

import (
	. "encoding/binary"
	"fmt"
	"math"
	"net"
	"reflect"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

func UintMin(x, y uint) uint {
	if x < y {
		return x
	}
	return y
}

func Mac2Uint64(mac net.HardwareAddr) uint64 {
	return uint64(BigEndian.Uint16(mac[:]))<<32 | uint64(BigEndian.Uint32(mac[2:]))
}

func Uint64ToMac(v uint64) net.HardwareAddr {
	bytes := [8]byte{}
	BigEndian.PutUint64(bytes[:], v)
	return net.HardwareAddr(bytes[2:])
}

func FindInterfaceByIp(ip string) *net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if strings.Contains(addr.String(), ip) {
				return &iface
			}
		}
	}
	return nil
}

func IsMulticast(mac []byte) bool {
	return mac[0]&0x1 == 1
}

func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func Max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

func Abs(n time.Duration) time.Duration {
	m := n >> 63
	return (n ^ m) - m
}

func IpToUint32(ip net.IP) uint32 {
	if len(ip) != net.IPv4len {
		return 0
	}
	return BigEndian.Uint32(ip)
}

func IpFromUint32(ipInt uint32) net.IP {
	ip := make([]byte, net.IPv4len)
	BigEndian.PutUint32(ip, ipInt)
	return ip
}

func GetIpHash(ip net.IP) uint32 {
	ipHash := uint32(0)
	for i := 0; i < len(ip); i += 4 {
		ipHash ^= *(*uint32)(unsafe.Pointer(&ip[i]))
	}
	return ipHash
}

func Bool2Int(b bool) int {
	if b {
		return 1
	}
	return 0
}

func Bool2UInt32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func Bool2UInt8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func MaskLenToNetmask(mask uint32) uint32 {
	return (math.MaxUint32) << (32 - mask)
}

func ParserStringIp(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4
	}
	return ip
}

func ParserStringIpV4(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	if ip = ip.To4(); ip == nil {
		return nil
	}
	return ip
}

func IpNetmaskFromStringCIDR(ipStr string) (net.IP, uint32, error) {
	_, r, err := net.ParseCIDR(ipStr)
	if err != nil {
		return nil, 0, err
	}
	maskInt, _ := r.Mask.Size()
	return r.IP, uint32(maskInt), nil
}

func IPv4ToBinary(ip uint32) string {
	var buf [32]byte
	for i := uint32(0); i < 32; i++ {
		if ip&(1<<i) != 0 {
			buf[31-i] = '1'
		} else {
			buf[31-i] = '0'
		}
	}
	return string(buf[:])
}

func IPv6ToBinary(ip net.IP) string {
	if len(ip) != 16 {
		panic(fmt.Sprintf("Invalid IPv6 address %v", ip))
	}
	var buf [128]byte
	for i := uint8(0); i < 128; i++ {
		if ip[15-i/8]&(1<<(i%8)) != 0 {
			buf[127-i] = '1'
		} else {
			buf[127-i] = '0'
		}
	}
	return string(buf[:])
}

// 运行环境信息
type RuntimeEnv struct {
	CpuNum     uint32
	MemorySize uint64

	// linux下为uname中Machine字段, 参照 https://en.wikipedia.org/wiki/Uname 和 https://stackoverflow.com/questions/45125516/possible-values-for-uname-m
	Arch string // 如 x86_64, aarch64, ppc64, armv7l, amd64, i686, i386, mips, sun4u

	// OS名称+版本号, 参照 github.com/shirou/gopsutil/v3/host/host_linux.go:PlatformInformationWithContext
	OS string // 如 ubuntu 11.04, centos 7.5.1804, fedora 19, redhat xx, linuxmint xx等

	// linux下为uname的Release字段
	KernelVersion string // 如 4.19.17
}

func GetRuntimeEnv() RuntimeEnv {
	cpuNum, err := cpu.Counts(true)
	if err != nil {
		cpuNum = runtime.NumCPU()
	}
	env := RuntimeEnv{
		CpuNum: uint32(cpuNum),
	}
	if v, err := mem.VirtualMemory(); err == nil {
		env.MemorySize = v.Total
	}
	if info, err := host.Info(); err == nil {
		env.Arch = info.KernelArch
		env.OS = info.Platform + " " + info.PlatformVersion
		env.KernelVersion = strings.Split(info.KernelVersion, "-")[0]
	}
	return env
}

func String(b []byte) (s string) {
	pbytes := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	pstring := (*reflect.StringHeader)(unsafe.Pointer(&s))
	pstring.Data = pbytes.Data
	pstring.Len = pbytes.Len
	return
}

func Slice(s string) (b []byte) {
	pbytes := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	pstring := (*reflect.StringHeader)(unsafe.Pointer(&s))
	pbytes.Data = pstring.Data
	pbytes.Len = pstring.Len
	pbytes.Cap = pstring.Len
	return
}
