package mapreduce

import (
	"time"
)

const (
	QUEUE_BATCH_SIZE = 4096
	FLUSH_INTERVAL   = time.Minute
)
