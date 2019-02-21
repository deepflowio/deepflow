package pcap

import (
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	libqueue "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet/queue"
)

type WorkerManager struct {
	inputQueue *queue.MultiQueue
	nQueues    int
	workers    []*Worker

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
	inputQueue *queue.MultiQueue,
	nQueues int,
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
		inputQueue: inputQueue,
		nQueues:    nQueues,
		workers:    make([]*Worker, nQueues),

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
	for i := 0; i < m.nQueues; i++ {
		worker := m.newWorker(i)
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
		// tick the workers
		m.inputQueue.Put(libqueue.HashKey(i), nil)
	}
	wg.Wait()
	return nil
}
