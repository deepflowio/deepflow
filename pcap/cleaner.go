package pcap

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	CLEAN_PERIOD = 5 * time.Minute
)

var (
	EXAMPLE_TEMPNAME        = getTempFilename(datatype.TAP_ISP, 0, 0, time.Duration(time.Now().UnixNano()))
	EXAMPLE_TEMPNAME_SPLITS = len(strings.Split(EXAMPLE_TEMPNAME, "_"))
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
				log.Debugf("Walk directory error: %s", err)
				// 返回nil，否则Walk()会中止
				return nil
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
		if err == nil {
			free := int64(fs.Bfree) * int64(fs.Bsize)
			for i := len(files) - nDeleted - 1; i >= 0 && free < c.diskFreeSpaceMargin; i-- {
				os.Remove(files[i].location)
				free += files[i].size
			}
		}
	}
}

func findLastRecordTime(file string) time.Duration {
	fp, err := os.Open(file)
	if err != nil {
		log.Warningf("Open %s failed: %s", file, err)
		return 0
	}
	defer fp.Close()

	if info, err := fp.Stat(); err != nil || info.Size() <= GLOBAL_HEADER_LEN+RECORD_HEADER_LEN {
		log.Warningf("Invalid content in file %s", file)
	}

	buffer := make([]byte, RECORD_HEADER_LEN)
	lastRecordTime := uint32(0)

	fp.Seek(GLOBAL_HEADER_LEN, io.SeekStart)
	for {
		if n, err := fp.Read(buffer); err != nil || n != RECORD_HEADER_LEN {
			break
		}
		second := binary.LittleEndian.Uint32(buffer[TS_SEC_OFFSET:])
		length := binary.LittleEndian.Uint32(buffer[INCL_LEN_OFFSET:])
		if second > lastRecordTime {
			lastRecordTime = second
		}
		fp.Seek(int64(length), io.SeekCurrent)
	}

	return time.Duration(lastRecordTime) * time.Second
}

func isTempFilename(name string) bool {
	return strings.HasSuffix(name, ".pcap.temp") && len(strings.Split(name, "_")) == EXAMPLE_TEMPNAME_SPLITS
}

func markAndCleanTempFiles(baseDirectory string, scanWg *sync.WaitGroup) {
	var files []string
	filepath.Walk(baseDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if info.IsDir() || !isTempFilename(name) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	scanWg.Done()

	// finish files gracefully
	for _, path := range files {
		lastPacketTime := findLastRecordTime(path)
		if lastPacketTime == 0 {
			log.Debugf("Remove empty or corrupted file %s", path)
			os.Remove(path)
			continue
		}
		newFilename := path[:len(path)-len(".pcap.temp")] + formatDuration(lastPacketTime) + ".pcap"
		os.Rename(path, newFilename)
	}
}

func (c *Cleaner) Start() {
	go c.work()
}
