package stats

import (
	"net"
	"time"
)

var (
	MinInterval = time.Second
)

type RemoteType = bool

const (
	REMOTE_TYPE_STATSD   = true
	REMOTE_TYPE_INFLUXDB = false
)

type Option = interface{}
type OptionStatTags = map[string]string
type OptionInterval time.Duration // must be time.Second, time.Minute or time.Hour

type Countable interface {
	// needs to be thread-safe, clear is required after read
	// accept struct or []StatItem
	GetCounter() interface{}

	// once closed, countable will be removed from stats
	Closed() bool
}

type Closable bool

func (c *Closable) Close() error {
	*c = Closable(true)
	return nil
}

func (c *Closable) Closed() bool {
	return bool(*c)
}

// 限定stats的最少interval，也就是不论注册Countable时
// 指定的Interval是多少，只要比此值低就优先使用此值
func SetMinInterval(interval time.Duration) {
	MinInterval = interval
}

// 指定influxdb远程服务器
// 只会有其中一个远程服务器会收到统计数据
func SetRemotes(addrs ...net.UDPAddr) {
	setRemotes(addrs...)
}

// 指定远程服务器类型，默认influxdb
func SetRemoteType(t RemoteType) {
	remoteType = t
}

func SetHostname(name string) {
	setHostname(name)
}

func RegisterPreHook(hook func()) {
	lock.Lock()
	preHooks = append(preHooks, hook)
	lock.Unlock()
}

func RegisterCountable(module string, countable Countable, opts ...Option) error {
	return registerCountable(module, countable, opts...)
}
