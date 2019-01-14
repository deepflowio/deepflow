// reference: https://my.oschina.net/ifraincoat/blog/604415
package utils

func BKDRHash(base uint64, str string) uint64 {
	seed := uint64(131) // 31 131 1313 13131 131313 etc..
	hash := base
	for i := 0; i < len(str); i++ {
		hash = (hash * seed) + uint64(str[i])
	}
	return hash
}

func SDBMHash(base uint64, str string) uint64 {
	hash := base
	for i := 0; i < len(str); i++ {
		hash = uint64(str[i]) + (hash << 6) + (hash << 16) - hash
	}
	return hash
}

func DJBHash(base uint64, str string) uint64 {
	hash := base
	for i := 0; i < len(str); i++ {
		hash = ((hash << 5) + hash) + uint64(str[i])
	}
	return hash
}

func APHash(base uint64, str string) uint64 {
	hash := uint64(0xAAAAAAAA) + base
	for i := 0; i < len(str); i++ {
		if (i & 1) == 0 {
			hash ^= ((hash << 7) ^ uint64(str[i])*(hash>>3))
		} else {
			hash ^= (^((hash << 11) + uint64(str[i]) ^ (hash >> 5)))
		}
	}
	return hash
}
