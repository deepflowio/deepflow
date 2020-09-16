package pcap

import (
	"time"
)

type Cleaner struct {
}

func NewCleaner(cleanPeriod time.Duration, maxDirectorySize, diskFreeSpaceMargin int64, baseDirectory string) *Cleaner {
	panic("")
}

func (c *Cleaner) UpdatePcapDataRetention(pcapDataRetention time.Duration) {
	panic("")
}

func (c *Cleaner) GetPcapDataRetention() time.Duration {
	panic("")
}

func (c *Cleaner) Start() {
}
