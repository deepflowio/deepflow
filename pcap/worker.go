package pcap

import (
	"fmt"
	"os"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

const (
	QUEUE_BATCH_SIZE = 1024
	BROADCAST_MAC    = datatype.MacInt(^uint64(0) >> 16)
	BROADCAST_IP     = datatype.IPv4Int(^uint32(0))
)

type WriterKey uint64

func getWriterKey(ipInt datatype.IPv4Int, aclGID datatype.ACLID, tapType zerodoc.TAPTypeEnum) WriterKey {
	return WriterKey((uint64(ipInt) << 32) | (uint64(aclGID) << 16) | uint64(tapType))
}

type WrappedWriter struct {
	*Writer

	tapType zerodoc.TAPTypeEnum
	aclGID  datatype.ACLID
	ip      datatype.IPv4Int
	mac     datatype.MacInt
	tid     int

	tempFilename    string
	firstPacketTime time.Duration
	lastPacketTime  time.Duration
}

type WorkerCounter struct {
	FileCreations        uint64 `statsd:"file_creations"`
	FileCloses           uint64 `statsd:"file_closes"`
	FileRejections       uint64 `statsd:"file_rejections"`
	FileCreationFailures uint64 `statsd:"file_creation_failures"`
	FileWritingFailures  uint64 `statsd:"file_writing_failures"`
	BufferedCount        uint64 `statsd:"buffered_count"`
	WrittenCount         uint64 `statsd:"written_count"`
	BufferedBytes        uint64 `statsd:"buffered_bytes"`
	WrittenBytes         uint64 `statsd:"written_bytes"`
}

type Worker struct {
	inputQueue queue.MultiQueueReader
	index      int
	queueKey   queue.HashKey

	maxConcurrentFiles int
	maxFileSize        int64
	maxFilePeriod      time.Duration
	baseDirectory      string

	*WorkerCounter

	writers map[WriterKey]*WrappedWriter

	writerBufferSize int
	tcpipChecksum    bool
}

func (m *WorkerManager) newWorker(index int) *Worker {
	return &Worker{
		inputQueue: m.inputQueue,
		index:      index,
		queueKey:   queue.HashKey(uint8(index)),

		maxConcurrentFiles: m.maxConcurrentFiles / m.nQueues,
		maxFileSize:        int64(m.maxFileSizeMB) << 20,
		maxFilePeriod:      time.Duration(m.maxFilePeriodSecond) * time.Second,
		baseDirectory:      m.baseDirectory,

		WorkerCounter: &WorkerCounter{},

		writers: make(map[WriterKey]*WrappedWriter),

		writerBufferSize: m.blockSizeKB << 10,
		tcpipChecksum:    m.tcpipChecksum,
	}
}

func isISP(inPort uint32) bool {
	return 0x10000 <= inPort && inPort < 0x20000
}

func isTOR(inPort uint32) bool {
	return 0x30000 <= inPort && inPort < 0x40000
}

func macToString(mac datatype.MacInt) string {
	return fmt.Sprintf("%012x", mac)
}

func ipToString(ip datatype.IPv4Int) string {
	return fmt.Sprintf("%03d%03d%03d%03d", uint8(ip>>24), uint8(ip>>16), uint8(ip>>8), uint8(ip))
}

func tapTypeToString(tapType zerodoc.TAPTypeEnum) string {
	switch tapType {
	case zerodoc.ISP0:
		return "isp0"
	case zerodoc.ISP1:
		return "isp1"
	case zerodoc.ISP2:
		return "isp2"
	case zerodoc.ToR:
		return "tor"
	default:
		panic("unsupported tap type")
	}
}

func formatDuration(d time.Duration) string {
	return time.Unix(0, int64(d)).Format(TIME_FORMAT)
}

func getTempFilename(tapType zerodoc.TAPTypeEnum, mac datatype.MacInt, ip datatype.IPv4Int, firstPacketTime time.Duration, index int) string {
	return fmt.Sprintf("%s_%s_%s_%s_.%d.pcap.temp", tapTypeToString(tapType), macToString(mac), ipToString(ip), formatDuration(firstPacketTime), index)
}

func (w *WrappedWriter) getTempFilename(base string) string {
	return fmt.Sprintf("%s/%d/%s", base, w.aclGID, getTempFilename(w.tapType, w.mac, w.ip, w.firstPacketTime, w.tid))
}

func (w *WrappedWriter) getFilename(base string) string {
	return fmt.Sprintf("%s/%d/%s_%s_%s_%s_%s.%d.pcap", base, w.aclGID, tapTypeToString(w.tapType), macToString(w.mac), ipToString(w.ip), formatDuration(w.firstPacketTime), formatDuration(w.lastPacketTime), w.tid)
}

func (w *Worker) shouldCloseFile(writer *WrappedWriter, packet *datatype.MetaPacket) bool {
	// check for file size and time
	if writer.FileSize()+int64(writer.BufferSize()) >= w.maxFileSize {
		return true
	}
	if packet.Timestamp-writer.firstPacketTime > w.maxFilePeriod {
		return true
	}
	return false
}

func (w *Worker) finishWriter(writer *WrappedWriter, newFilename string) {
	writer.Close()
	counter := writer.GetAndResetStats()
	w.BufferedCount += counter.totalBufferedCount
	w.WrittenCount += counter.totalWrittenCount
	w.BufferedBytes += counter.totalBufferedBytes
	w.WrittenBytes += counter.totalWrittenBytes
	log.Debugf("Finish writing %s, renaming to %s", writer.tempFilename, newFilename)
	os.Rename(writer.tempFilename, newFilename)
	w.FileCloses++
}

func (w *Worker) writePacket(packet *datatype.MetaPacket, tapType zerodoc.TAPTypeEnum, ip datatype.IPv4Int, mac datatype.MacInt, aclGID datatype.ACLID) {
	key := getWriterKey(ip, aclGID, tapType)
	writer, exist := w.writers[key]
	if exist && w.shouldCloseFile(writer, packet) {
		newFilename := writer.getFilename(w.baseDirectory)
		w.finishWriter(writer, newFilename)
		delete(w.writers, key)
		exist = false
	}
	if !exist {
		if len(w.writers) >= w.maxConcurrentFiles {
			log.Debugf("Max concurrent file (%d files) exceeded", w.maxConcurrentFiles)
			w.FileRejections++
			return
		}
		directory := fmt.Sprintf("%s/%d", w.baseDirectory, aclGID)
		if _, err := os.Stat(directory); os.IsNotExist(err) {
			os.MkdirAll(directory, os.ModePerm)
		}
		writer = &WrappedWriter{
			tapType:         tapType,
			aclGID:          aclGID,
			ip:              ip,
			mac:             mac,
			tid:             w.index,
			firstPacketTime: packet.Timestamp,
			lastPacketTime:  packet.Timestamp,
		}
		writer.tempFilename = writer.getTempFilename(w.baseDirectory)
		log.Debugf("Begin to write packets to %s", writer.tempFilename)
		// TODO: 池化writer（有一个[65536]byte）
		var err error
		if writer.Writer, err = NewWriter(writer.tempFilename, w.writerBufferSize, w.tcpipChecksum); err != nil {
			log.Debugf("Failed to create writer for %s: %s", writer.tempFilename, err)
			w.FileCreationFailures++
			return
		}
		w.writers[key] = writer
		w.FileCreations++
	}
	if err := writer.Write(packet); err != nil {
		log.Debugf("Failed to write packet to %s: %s", writer.tempFilename, err)
		w.FileWritingFailures++
		return
	}
	counter := writer.GetAndResetStats()
	w.BufferedCount += counter.totalBufferedCount
	w.WrittenCount += counter.totalWrittenCount
	w.BufferedBytes += counter.totalBufferedBytes
	w.WrittenBytes += counter.totalWrittenBytes
	writer.lastPacketTime = packet.Timestamp
}

func (w *Worker) Process() {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)
	ips := make([]datatype.IPv4Int, 0, 2)
	macs := make([]datatype.MacInt, 0, 2)

	for {
		n := w.inputQueue.Gets(w.queueKey, elements)
		timeNow := time.Duration(time.Now().UnixNano())
		for _, e := range elements[:n] {
			if e == nil { // tick
				for key, writer := range w.writers {
					if timeNow-writer.firstPacketTime > w.maxFilePeriod {
						newFilename := writer.getFilename(w.baseDirectory)
						w.finishWriter(writer, newFilename)
						delete(w.writers, key)
					}
				}
				continue
			}

			packet := e.(*datatype.MetaPacket)

			if packet.PolicyData == nil || packet.EndpointData == nil { // shouldn't happen
				log.Warningf("drop invalid packet with nil PolicyData or EndpointData %v", packet)
				datatype.ReleaseMetaPacket(packet)
				continue
			}

			ips = ips[:0]
			macs = macs[:0]
			var tapType zerodoc.TAPTypeEnum
			if isISP(packet.InPort) {
				tapType = zerodoc.TAPTypeEnum(packet.InPort - 0x10000)
				if packet.EndpointData.SrcInfo.L3EpcId != 0 && packet.IpSrc != BROADCAST_IP && packet.MacSrc != BROADCAST_MAC {
					ips = append(ips, packet.IpSrc)
					macs = append(macs, packet.MacSrc)
				}
				if packet.EndpointData.DstInfo.L3EpcId != 0 && packet.IpDst != BROADCAST_IP && packet.MacDst != BROADCAST_MAC {
					ips = append(ips, packet.IpDst)
					macs = append(macs, packet.MacDst)
				}
			} else if isTOR(packet.InPort) {
				tapType = zerodoc.ToR
				if packet.EndpointData.SrcInfo.L2End && packet.IpSrc != BROADCAST_IP && packet.MacSrc != BROADCAST_MAC {
					ips = append(ips, packet.IpSrc)
					macs = append(macs, packet.MacSrc)
				}
				if packet.EndpointData.DstInfo.L2End && packet.IpDst != BROADCAST_IP && packet.MacDst != BROADCAST_MAC {
					ips = append(ips, packet.IpDst)
					macs = append(macs, packet.MacDst)
				}
			} else {
				datatype.ReleaseMetaPacket(packet)
				continue
			}

			for _, policy := range packet.PolicyData.AclActions {
				if policy.GetACLGID() <= 0 {
					continue
				}
				if policy.GetActionFlags()&datatype.ACTION_PACKET_CAPTURING != 0 {
					for i := range ips {
						w.writePacket(packet, tapType, ips[i], macs[i], policy.GetACLGID())
					}
				}
			}

			datatype.ReleaseMetaPacket(packet)
		}
	}
}

func (w *Worker) Close() error {
	log.Infof("Stop pcap worker (%d) writing to %d files", w.index, len(w.writers))
	for _, writer := range w.writers {
		newFilename := writer.getFilename(w.baseDirectory)
		w.finishWriter(writer, newFilename)
	}
	w.writers = nil
	return nil
}

func (w *Worker) GetCounter() interface{} {
	counter := &WorkerCounter{}
	counter, w.WorkerCounter = w.WorkerCounter, counter
	return counter
}

func (w *Worker) Closed() bool {
	return w.writers == nil
}
