package pcap

import (
	"io"
	"os"
	"strconv"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

type WorkerManager struct {
	inputQueue queue.MultiQueueReader
	nQueues    int

	maxConcurrentFiles    int
	maxFileSizeMB         int
	maxFilePeriodSecond   int
	maxDirectorySizeGB    int
	diskFreeSpaceMarginGB int
	maxFileKeepDay        int
	baseDirectory         string
}

func NewWorkerManager(
	inputQueue queue.MultiQueueReader,
	nQueues int,
	maxConcurrentFiles int,
	maxFileSizeMB int,
	maxFilePeriodSecond int,
	maxDirectorySizeGB int,
	diskFreeSpaceMarginGB int,
	maxFileKeepDay int,
	baseDirectory string,
) *WorkerManager {
	return &WorkerManager{
		inputQueue: inputQueue,
		nQueues:    nQueues,

		maxConcurrentFiles:    maxConcurrentFiles,
		maxFileSizeMB:         maxFileSizeMB,
		maxFilePeriodSecond:   maxFilePeriodSecond,
		maxDirectorySizeGB:    maxDirectorySizeGB,
		diskFreeSpaceMarginGB: diskFreeSpaceMarginGB,
		maxFileKeepDay:        maxFileKeepDay,
		baseDirectory:         baseDirectory,
	}
}

func (m *WorkerManager) newWorker(index int) *Worker {
	return &Worker{
		inputQueue: m.inputQueue,
		queueKey:   queue.HashKey(uint8(index)),

		maxConcurrentFiles: m.maxConcurrentFiles / m.nQueues,
		maxFileSize:        int64(m.maxFileSizeMB) << 20,
		maxFilePeriod:      time.Duration(m.maxFilePeriodSecond) * time.Second,
		baseDirectory:      m.baseDirectory,

		WorkerCounter: &WorkerCounter{},

		writers: make(map[WriterKey]*WrappedWriter),
	}
}

func (m *WorkerManager) Start() []io.Closer {
	os.MkdirAll(m.baseDirectory, os.ModePerm)
	NewCleaner(int64(m.maxDirectorySizeGB)<<30, int64(m.diskFreeSpaceMarginGB)<<30, time.Duration(m.maxFileKeepDay)*time.Hour*24, m.baseDirectory).Start()
	closers := make([]io.Closer, m.nQueues)
	for i := 0; i < m.nQueues; i++ {
		worker := m.newWorker(i)
		stats.RegisterCountable("pcap", worker, stats.OptionStatTags{"index": strconv.Itoa(i)})
		closers[i] = io.Closer(worker)
		go worker.Process()
	}
	return closers
}
