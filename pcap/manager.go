package pcap

import (
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

type WorkerManager struct {
	packetQueueReaders []queue.QueueReader
	packetQueueWriters []queue.QueueWriter
	workers            []*Worker

	tcpipChecksum         bool
	blockSizeKB           int
	maxConcurrentFiles    int
	maxFileSizeMB         int
	maxFilePeriodSecond   int
	maxDirectorySizeGB    int
	diskFreeSpaceMarginGB int
	maxFileKeepDay        int
	baseDirectory         string
}

func NewWorkerManager(
	packetQueueReaders []queue.QueueReader,
	packetQueueWriters []queue.QueueWriter,
	tcpipChecksum bool,
	blockSizeKB int,
	maxConcurrentFiles int,
	maxFileSizeMB int,
	maxFilePeriodSecond int,
	maxDirectorySizeGB int,
	diskFreeSpaceMarginGB int,
	maxFileKeepDay int,
	baseDirectory string,
) *WorkerManager {
	return &WorkerManager{
		packetQueueReaders: packetQueueReaders,
		packetQueueWriters: packetQueueWriters,
		workers:            make([]*Worker, len(packetQueueReaders)),

		tcpipChecksum:         tcpipChecksum,
		blockSizeKB:           blockSizeKB,
		maxConcurrentFiles:    maxConcurrentFiles,
		maxFileSizeMB:         maxFileSizeMB,
		maxFilePeriodSecond:   maxFilePeriodSecond,
		maxDirectorySizeGB:    maxDirectorySizeGB,
		diskFreeSpaceMarginGB: diskFreeSpaceMarginGB,
		maxFileKeepDay:        maxFileKeepDay,
		baseDirectory:         baseDirectory,
	}
}

func (m *WorkerManager) Start() []io.Closer {
	os.MkdirAll(m.baseDirectory, os.ModePerm)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go markAndCleanTempFiles(m.baseDirectory, wg)
	wg.Wait()

	NewCleaner(int64(m.maxDirectorySizeGB)<<30, int64(m.diskFreeSpaceMarginGB)<<30, time.Duration(m.maxFileKeepDay)*time.Hour*24, m.baseDirectory).Start()
	for i := 0; i < len(m.packetQueueReaders); i++ {
		worker := m.newWorker(queue.HashKey(i))
		m.workers[i] = worker
		stats.RegisterCountable("pcap", worker, stats.OptionStatTags{"index": strconv.Itoa(i)})
		go worker.Process()
	}
	return []io.Closer{m}
}

func (m *WorkerManager) Close() error {
	wg := sync.WaitGroup{}
	wg.Add(len(m.workers))
	for _, w := range m.workers {
		go func(worker *Worker, waitGroup *sync.WaitGroup) {
			worker.Close()
			waitGroup.Done()
		}(w, &wg)
	}
	time.Sleep(time.Second)
	for i := range m.workers {
		// FIXME: 统一用queue发送nil处理所有goroutine的结束，以避免持有QueueWriter
		// tick the workers
		m.packetQueueWriters[i].Put(nil)
	}
	wg.Wait()
	return nil
}
