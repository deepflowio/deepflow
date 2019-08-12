package tag

import (
	"fmt"

	. "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

// GetFastID 返回两个uint64的ID，若tag的code不在fast ID的范围内会panic
// 注意：不同APP的GetFastID可以返回相同的值
// FIXME: 不支持IPv6，预计droplet/app在v5.5.6中支持
func GetFastID(t *Tag) (uint64, uint64) {
	switch t.Code & ^CodeIndices {
	// key0: ACLGID | ACLDirection | Direction | TAPType | ISPCode
	case ACLGID | ACLDirection | Direction | TAPType | ISPCode | IP: // geo
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.ISP&0xFF)<<25
		key1 := uint64(t.IP)
		return key0 | uint64(1&0x7)<<61, key1
	case ACLGID | ACLDirection | Direction | TAPType | ISPCode | IPPath: // geo
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.ISP&0xFF)<<25
		key1 := uint64(t.IP) | uint64(t.IP1)<<32
		return key0 | uint64(2&0x7)<<61, key1

	// key0: ACLGID | ACLDirection | Direction | TAPType | Region
	case ACLGID | ACLDirection | Direction | TAPType | Region | IP: // geo
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Region&0xFF)<<25
		key1 := uint64(t.IP)
		return key0 | uint64(3&0x7)<<61, key1
	case ACLGID | ACLDirection | Direction | TAPType | Region | IPPath: // geo
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Region&0xFF)<<25
		key1 := uint64(t.IP) | uint64(t.IP1)<<32
		return key0 | uint64(4&0x7)<<61, key1

	// key0: ACLGID | ACLDirection | Direction | TAPType
	case ACLGID | ACLDirection | Direction | TAPType | IP: // fps, perf, type, usage
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20
		key1 := uint64(t.IP)
		return key0 | uint64(1&0x7)<<61, key1
	case ACLGID | ACLDirection | Direction | TAPType | IPPath: // fps, perf, type, usage
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20
		key1 := uint64(t.IP) | (uint64(t.IP1) << 32)
		return key0 | uint64(2&0x7)<<61, key1

	// key0: ACLGID | ACLDirection | Direction | TAPType | Protocol | ServerPort
	case ACLGID | ACLDirection | Direction | TAPType | Protocol | ServerPort | IP: // usage
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Protocol&0xFF)<<25 | uint64(t.ServerPort&0xFFFF)<<33
		key1 := uint64(t.IP)
		return key0 | uint64(3&0x7)<<61, key1
	case ACLGID | ACLDirection | Direction | TAPType | Protocol | ServerPort | IPPath: // fps, perf, usage
		key0 := uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Protocol&0xFF)<<25 | uint64(t.ServerPort&0xFFFF)<<33
		key1 := uint64(t.IP) | (uint64(t.IP1) << 32)
		return key0 | uint64(4&0x7)<<61, key1

	// key0: L3EpcIDPath | TAPType | Protocol | ServerPort
	case L3EpcIDPath | TAPType | Protocol | ServerPort | IPPath: // log_usage
		key0 := uint64(uint16(t.L3EpcID)) | uint64(uint16(t.L3EpcID1))<<16 | uint64(t.TAPType&0x1F)<<32 | uint64(t.Protocol&0xFF)<<37 | uint64(t.ServerPort&0xFFFF)<<45
		key1 := uint64(t.IP) | (uint64(t.IP1) << 32)
		return key0 | uint64(1&0x7)<<61, key1

	default:
		panic(fmt.Sprintf("需要更新GetFastID %016x", t.Code))
	}
}
