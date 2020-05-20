package geo

const MIN_MASKLEN = 16
const MAX_MASKLEN = 32

type maxMask [1 << MIN_MASKLEN]uint8

type netmaskTree struct {
	maxMask
	cache map[uint32]uint16
}

var maskLenToNetmask [MAX_MASKLEN + 1]uint32

func init() {
	// fill maskLenToNetmask with {0x00000000, 0x80000000, 0xC0000000, ...}
	var rMask uint32 = 0xFFFFFFFF
	for i := 0; i <= MAX_MASKLEN; i++ {
		maskLenToNetmask[i] = ^rMask
		rMask >>= 1
	}
}

func getFirstMask(start, end uint32) (uint32, uint8) {
	maxLen := MAX_MASKLEN
	for ; maxLen > MIN_MASKLEN; maxLen-- {
		if start&(1<<uint32(MAX_MASKLEN-maxLen)) != 0 {
			// maxLen继续减少将会使得start不是所在网段的第一个IP
			break
		}
		if start+^maskLenToNetmask[maxLen] >= end || start+^maskLenToNetmask[maxLen-1] > end {
			// maxLen继续减少将会使得网段包含end之后的IP
			break
		}
	}
	return start, uint8(maxLen)
}

func (c *maxMask) updateMask(start, end uint32) {
	for end >= start {
		prefix, maskLen := getFirstMask(start, end)
		key := prefix >> (MAX_MASKLEN - MIN_MASKLEN)
		if maskLen > c[key] {
			c[key] = maskLen
		}
		start += 1 << uint32(MAX_MASKLEN-maskLen)
	}
}

func (c *maxMask) getMask(ip uint32) uint8 {
	// mask为0的情况只在整段地址都没有记录的情况下出现，这时候的cacheKey变为0.0.0.0，是安全的
	return c[ip>>(MAX_MASKLEN-MIN_MASKLEN)]
}

func NewNetmaskGeoTree() GeoTree {
	nTree := &netmaskTree{}
	log.Infof("Geo cache setup ...")

	for _, geoInfo := range GEO_ENTRIES {
		nTree.maxMask.updateMask(geoInfo.IPStart, geoInfo.IPEnd)
	}

	cache := make(map[uint32]uint16)
	for _, e := range GEO_ENTRIES {
		for ip := e.IPStart; ip <= e.IPEnd && ip > 0; {
			mask := nTree.maxMask.getMask(ip)
			key := ip & maskLenToNetmask[mask]
			cache[key] = uint16(e.Region)<<8 | uint16(e.ISP)
			ip += 1 << (MAX_MASKLEN - uint32(mask))
		}
	}
	nTree.cache = cache

	log.Infof("Geo cache size: %d", len(cache))
	return nTree
}

func (t *netmaskTree) Query(ip uint32) (uint8, uint8) {
	maxMask := t.maxMask.getMask(ip)
	cacheKey := ip & maskLenToNetmask[maxMask]
	if v, in := t.cache[cacheKey]; in {
		return uint8(v >> 8), uint8(v & 0xff)
	}
	return 0, 0
}
