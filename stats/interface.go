package stats

import (
	"bytes"
	"net"
	"time"
)

type StatType uint8

const (
	COUNT_TYPE StatType = iota
	GAUGE_TYPE
)

var (
	MinInterval = time.Second
)

type StatsOption = interface{}

type OptionStatTags map[string]string
type OptionInterval time.Duration

func (t *OptionStatTags) String() string {
	if len(*t) == 0 {
		return "{}"
	}
	var strBuf bytes.Buffer
	strBuf.WriteString("{")
	for key, value := range *t {
		strBuf.WriteString(key + ": " + value + ", ")
	}
	strBuf.Truncate(strBuf.Len() - 2)
	return strBuf.String() + "}"
}

type Countable interface {
	// needs to be thread-safe, clear is required after read
	// accept struct or []StatItem
	GetCounter() interface{}
}

// 限定stats的最少interval，也就是不论注册Countable时
// 指定的Interval是多少，只要比此值低就优先使用此值
func SetMinInterval(interval time.Duration) {
	MinInterval = interval
}

// 指定stats远程服务器地址
func SetRemotes(ip ...net.IP) {
	setRemotes(ip...)
}

func SetHostname(name string) {
	setHostname(name)
}

func RegisterCountable(module string, countable Countable, opts ...StatsOption) error {
	return registerCountable(module, countable, opts...)
}

func DeregisterCountable(countable Countable) {
	deregisterCountable(countable)
}
