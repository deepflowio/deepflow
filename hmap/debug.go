package hmap

import (
	"fmt"
	"strings"
	"sync"
)

type Debug interface {
	KeySize() int
	GetCollisionChain() []byte
	SetCollisionChainDebugThreshold(int)
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
	if len(chain) == 0 {
		return ""
	}
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

var debugItemMutex sync.Mutex
var debugItems []Debug

func RegisterForDebug(d ...Debug) {
	debugItemMutex.Lock()
	debugItems = append(debugItems, d...)
	debugItemMutex.Unlock()
}

func DeregisterForDebug(ds ...Debug) {
	debugItemMutex.Lock()
	for _, d := range ds {
		index := -1
		for i, item := range debugItems {
			if item == d {
				index = i
				break
			}
		}
		if index == -1 {
			continue
		}
		length := len(debugItems)
		if index < length-1 {
			copy(debugItems[index:], debugItems[index+1:])
		}
		debugItems = debugItems[:length-1]
	}
	debugItemMutex.Unlock()
}

func SetCollisionChainDebugThreshold(t int) {
	debugItemMutex.Lock()
	for _, d := range debugItems {
		d.SetCollisionChainDebugThreshold(t)
	}
	debugItemMutex.Unlock()
}
