package lru

import (
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("lru")

const (
	_BLOCK_SIZE_BITS = 8
	_BLOCK_SIZE      = 1 << _BLOCK_SIZE_BITS
	_BLOCK_SIZE_MASK = _BLOCK_SIZE - 1
)

func minPowerOfTwo(v int) (int, int) {
	for i := 0; i < 30; i++ {
		if v <= 1<<uint64(i) {
			return 1 << uint64(i), i
		}
	}
	return 1, 0
}
