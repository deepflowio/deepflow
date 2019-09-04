package idmap

const (
	blockSizeBits = 8
	blockSize     = 1 << blockSizeBits
	blockSizeMask = blockSize - 1
)
