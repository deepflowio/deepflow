package hmap

import (
	"fmt"
	"strings"
)

type Debug interface {
	KeySize() int
	GetCollisionChain() []byte
}

func dumpHexBytes(bs []byte) string {
	sb := strings.Builder{}
	sb.WriteString("0x")
	isZero := true
	for _, b := range bs {
		if isZero {
			if b == 0 {
				continue
			} else {
				isZero = false
				sb.WriteString(fmt.Sprintf("%x", b))
			}
		} else {
			sb.WriteString(fmt.Sprintf("%02x", b))
		}
	}
	if isZero {
		sb.WriteRune('0')
	}
	return sb.String()
}

func DumpCollisionChain(d Debug) string {
	chain := d.GetCollisionChain()
	keySize := d.KeySize()
	nKeys := len(chain) / keySize
	keys := make([]string, 0, nKeys)
	for i := 0; i < nKeys; i++ {
		if i < nKeys-1 {
			keys = append(keys, dumpHexBytes(chain[i*keySize:(i+1)*keySize]))
		} else {
			keys = append(keys, dumpHexBytes(chain[i*keySize:]))
		}
	}
	return strings.Join(keys, "-")
}
