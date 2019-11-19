package tag

import (
	"encoding/binary"
	"fmt"
	"net"

	. "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

const (
	_OTHERS_KEY_LEN = 8
	_V4_IP_PATH_LEN = net.IPv4len * 2
	_V6_IP_PATH_LEN = net.IPv6len * 2
	_V4_KEY_LEN     = _V4_IP_PATH_LEN + _OTHERS_KEY_LEN
	_V6_KEY_LEN     = _V6_IP_PATH_LEN + _OTHERS_KEY_LEN
)

func getIPKey(t *Tag, keys []byte) {
	if t.IsIPv6 != 0 {
		// 消除边界检查
		_ = keys[_V6_IP_PATH_LEN-1]
		copy(keys, t.IP6)
		if t.Code&IPPath != 0 {
			copy(keys[net.IPv6len:], t.IP61)
		}
	} else {
		_ = keys[_V4_IP_PATH_LEN-1]
		binary.BigEndian.PutUint32(keys, t.IP)
		if t.Code&IPPath != 0 {
			binary.BigEndian.PutUint32(keys[net.IPv4len:], t.IP1)
		}
	}
}

// GetFastID 返回ID，若tag的code不在fast ID的范围内会panic
// 对于IPv4，传入的keys长度应为16
// 对于IPv6，传入的keys长度应为40
// 注意：不同APP的GetFastID可以返回相同的值
func GetFastID(t *Tag, keys []byte) {
	var codeID uint8
	var keyOthers uint64
	switch t.Code & ^CodeIndices {
	// keyOthers: ACLGID | ACLDirection | Direction | TAPType | ISPCode
	case ACLGID | ACLDirection | Direction | TAPType | ISPCode | IP: // geo
		codeID = 0
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.ISP&0xFF)<<25
	case ACLGID | ACLDirection | Direction | TAPType | ISPCode | IPPath: // geo
		codeID = 1
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.ISP&0xFF)<<25

	// keyOthers: ACLGID | ACLDirection | Direction | TAPType | ISPCode | Protocol | ServerPort
	case ACLGID | ACLDirection | Direction | TAPType | ISPCode | Protocol | ServerPort | IP: // geo
		codeID = 2
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.ISP&0xFF)<<25 | uint64(t.Protocol&0xFF)<<33 | uint64(t.ServerPort&0xFFFF)<<41
	case ACLGID | ACLDirection | Direction | TAPType | ISPCode | Protocol | ServerPort | IPPath: // geo
		codeID = 3
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.ISP&0xFF)<<25 | uint64(t.Protocol&0xFF)<<33 | uint64(t.ServerPort&0xFFFF)<<41

	// keyOthers: ACLGID | ACLDirection | Direction | TAPType | Region
	case ACLGID | ACLDirection | Direction | TAPType | Region | IP: // geo
		codeID = 4
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Region&0xFF)<<25
	case ACLGID | ACLDirection | Direction | TAPType | Region | IPPath: // geo
		codeID = 5
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Region&0xFF)<<25

	// keyOthers: ACLGID | ACLDirection | Direction | TAPType | Region | Protocol | ServerPort
	case ACLGID | ACLDirection | Direction | TAPType | Region | Protocol | ServerPort | IP: // geo
		codeID = 6
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Region&0xFF)<<25 | uint64(t.Protocol&0xFF)<<33 | uint64(t.ServerPort&0xFFFF)<<41
	case ACLGID | ACLDirection | Direction | TAPType | Region | Protocol | ServerPort | IPPath: // geo
		codeID = 7
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Region&0xFF)<<25 | uint64(t.Protocol&0xFF)<<33 | uint64(t.ServerPort&0xFFFF)<<41

	// keyOthers: ACLGID | ACLDirection | Direction | TAPType
	case ACLGID | ACLDirection | Direction | TAPType | IP:
		codeID = 1
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20
	case ACLGID | ACLDirection | Direction | TAPType | IPPath:
		codeID = 2
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20

	// keyOthers: ACLGID | ACLDirection | Direction | TAPType | Protocol | ServerPort
	case ACLGID | ACLDirection | Direction | TAPType | Protocol | ServerPort | IP:
		codeID = 3
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Protocol&0xFF)<<25 | uint64(t.ServerPort&0xFFFF)<<33
	case ACLGID | ACLDirection | Direction | TAPType | Protocol | ServerPort | IPPath:
		codeID = 4
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18 | uint64(t.TAPType&0x1F)<<20 | uint64(t.Protocol&0xFF)<<25 | uint64(t.ServerPort&0xFFFF)<<33

	// keyOthers: ACLGID | ACLDirection | Direction (没有IP)
	case ACLGID | ACLDirection | Direction:
		codeID = 5
		keyOthers = uint64(t.ACLGID&0xFFFF) | uint64(t.ACLDirection&0x3)<<16 | uint64(t.Direction&0x3)<<18

	// keyOthers: L3EpcIDPath | TAPType | Protocol | ServerPort
	case L3EpcIDPath | TAPType | Protocol | ServerPort | IPPath: // log_usage
		codeID = 1
		keyOthers = uint64(uint16(t.L3EpcID)) | uint64(uint16(t.L3EpcID1))<<16 | uint64(t.TAPType&0x1F)<<32 | uint64(t.Protocol&0xFF)<<37 | uint64(t.ServerPort&0xFFFF)<<45

	default:
		panic(fmt.Sprintf("需要更新GetFastID %016x", t.Code))
	}

	keyOthers |= uint64(codeID&0x7) << 61
	binary.BigEndian.PutUint64(keys, keyOthers)
	getIPKey(t, keys[_OTHERS_KEY_LEN:])
}
