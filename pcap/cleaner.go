package pcap

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	CLEAN_PERIOD = 5 * time.Minute
)

type File struct {
	location string
	fileTime time.Time
	size     int64
}

type Cleaner struct {
	maxDirectorySize    int64
	diskFreeSpaceMargin int64
	timeToLive          time.Duration
	baseDirectory       string
}

func NewCleaner(maxDirectorySize, diskFreeSpaceMargin int64, timeToLive time.Duration, baseDirectory string) *Cleaner {
	return &Cleaner{
		maxDirectorySize:    maxDirectorySize,
		diskFreeSpaceMargin: diskFreeSpaceMargin,
		timeToLive:          timeToLive,
		baseDirectory:       baseDirectory,
	}
}

func (c *Cleaner) work() {
	var files []File
	for range time.Tick(CLEAN_PERIOD) {
		files = files[:0]
		filepath.Walk(c.baseDirectory, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			name := info.Name()
			if info.IsDir() || !strings.HasSuffix(name, ".pcap") {
				return nil
			}
			segs := strings.Split(name[:len(name)-len(".pcap")], "_")
			if fileTime, err := time.Parse(TIME_FORMAT, segs[len(segs)-1]); err != nil {
				log.Warningf("Incorrect name for file %s", path)
			} else {
				files = append(files, File{
					location: path,
					fileTime: fileTime,
					size:     info.Size(),
				})
			}
			return nil
		})
		// 用结束写入时间倒排
		sort.Slice(files, func(i, j int) bool { return files[i].fileTime.Sub(files[j].fileTime) > 0 })

		// check delete
		now := time.Now()
		sumSize := int64(0)
		nDeleted := 0
		for _, f := range files {
			sumSize += f.size
			if sumSize >= c.maxDirectorySize || now.Sub(f.fileTime) > c.timeToLive {
				os.Remove(f.location)
				nDeleted++
			}
		}

		fs := syscall.Statfs_t{}
		err := syscall.Statfs(c.baseDirectory, &fs)
		if err != nil {
			free := int64(fs.Bfree) * int64(fs.Bsize)
			for i := len(files) - nDeleted - 1; i >= 0 && free < c.diskFreeSpaceMargin; i-- {
				os.Remove(files[i].location)
				free += files[i].size
			}
		}
	}
}

func (c *Cleaner) Start() {
	go c.work()
}
