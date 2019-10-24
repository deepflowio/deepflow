package adapter

type PacketCounter struct {
	RxPackets uint64 `statsd:"rx_packets"`
	RxDropped uint64 `statsd:"rx_dropped"` // 当前SEQ减去上次的SEQ
	RxExpired uint64 `statsd:"rx_expired"` // 当前SEQ小于上次的SEQ时+1，包乱序并且超出了CACHE_SIZE
	RxErrors  uint64 `statsd:"rx_errors"`  // 错误的包

	TxPackets uint64 `statsd:"tx_packets"`
}

type statsCounter struct {
	counter *PacketCounter
	stats   *PacketCounter
}

func (c *PacketCounter) add(i *PacketCounter) {
	c.RxPackets += i.RxPackets
	c.RxDropped += i.RxDropped
	c.RxExpired += i.RxExpired
	c.RxErrors += i.RxErrors
	c.TxPackets += i.TxPackets
}

func (c *statsCounter) init() {
	c.counter = &PacketCounter{}
	c.stats = &PacketCounter{}
}

func (c *statsCounter) GetStatsCounter() interface{} {
	return c.stats
}

func (c *statsCounter) GetCounter() interface{} {
	counter := &PacketCounter{}
	counter, c.counter = c.counter, counter
	return counter
}
