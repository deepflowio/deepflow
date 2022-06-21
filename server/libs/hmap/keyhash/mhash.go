package keyhash

func hashRotate(x uint32, k uint) uint32 {
	return (x << k) | (x >> (32 - k))
}

func mhashAddInner(hash, data uint32) uint32 {
	if data == 0 {
		return hash
	}
	data *= 0xcc9e2d51
	data = hashRotate(data, 15)
	data *= 0x1b873593
	return hash ^ data
}

func mhashAdd(hash, data uint32) uint32 {
	hash = mhashAddInner(hash, data)
	hash = hashRotate(hash, 13)
	return hash*5 + 0xe6546b64
}

func mhashFinish(hash uint32) uint32 {
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16
	return hash
}

func HashAdd(hash, data uint32) uint32 {
	return mhashAdd(hash, data)
}

func HashFinish(hash uint32) uint32 {
	return mhashFinish(hash)
}
