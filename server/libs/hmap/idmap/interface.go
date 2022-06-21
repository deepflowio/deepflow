package idmap

type UBigIDMap interface {
	AddOrGetWithSlice(key []byte, hash uint32, value uint32, overwrite bool) (uint32, bool)
	GetWithSlice(key []byte, hash uint32) (uint32, bool)

	Size() int
	Width() int
	Clear()
}
