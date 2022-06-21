package pcap

import (
	"time"
)

type Cleaner struct {
}

func NewCleaner(cleanPeriod time.Duration, maxDirectorySize, diskFreeSpaceMargin int64, baseDirectory string) *Cleaner {
	return &Cleaner{}
}

func (c *Cleaner) UpdatePcapDataRetention(pcapDataRetention time.Duration) {
}

func (c *Cleaner) GetPcapDataRetention() time.Duration {
	return 0
}

func (c *Cleaner) Start() {
}
