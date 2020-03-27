package pcap

import (
	"container/list"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/op/go-logging"

	. "github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

const (
	QUEUE_BATCH_SIZE = 1024
	BROADCAST_MAC    = datatype.MacInt(^uint64(0) >> 16)
	BROADCAST_IP     = datatype.IPv4Int(^uint32(0))
)

type WriterKey uint64

func getWriterIpv6Key(ip net.IP, aclGID uint16, tapType zerodoc.TAPTypeEnum) WriterKey {
	ipHash := uint32(0)
	for i := 0; i < len(ip); i += 4 {
		ipHash ^= *(*uint32)(unsafe.Pointer(&ip[i]))
	}
	return WriterKey((uint64(ipHash) << 32) | (uint64(aclGID) << 16) | uint64(tapType))
}

func getWriterKey(ipInt datatype.IPv4Int, aclGID uint16, tapType zerodoc.TAPTypeEnum) WriterKey {
	return WriterKey((uint64(ipInt) << 32) | (uint64(aclGID) << 16) | uint64(tapType))
}

type WrappedWriter struct {
	*Writer

	tapType zerodoc.TAPTypeEnum
	aclGID  uint16
	ip      datatype.IPv4Int
	ip6     net.IP
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
	packetQueue queue.QueueReader
	index       int

	maxConcurrentFiles int
	maxFileSize        int64
	maxFilePeriod      time.Duration
	baseDirectory      string

	*WorkerCounter

	writers     map[WriterKey]*WrappedWriter
	writersIpv6 map[WriterKey]*list.List

	ips  []datatype.IPv4Int
	ip6s []net.IP
	macs []datatype.MacInt

	writerBufferSize int
	tcpipChecksum    bool

	exiting bool
	exited  bool
	exitWg  *sync.WaitGroup
}

func (m *WorkerManager) newWorker(packetQueueID queue.HashKey) *Worker {
	return &Worker{
		packetQueue: m.packetQueueReaders[packetQueueID],
		index:       int(packetQueueID),

		maxConcurrentFiles: m.maxConcurrentFiles / len(m.packetQueueReaders),
		maxFileSize:        int64(m.maxFileSizeMB) << 20,
		maxFilePeriod:      time.Duration(m.maxFilePeriodSecond) * time.Second,
		baseDirectory:      m.baseDirectory,

		WorkerCounter: &WorkerCounter{},

		writers:     make(map[WriterKey]*WrappedWriter),
		writersIpv6: make(map[WriterKey]*list.List),

		ips:  make([]datatype.IPv4Int, 0, 2),
		ip6s: make([]net.IP, 0, 2),
		macs: make([]datatype.MacInt, 0, 2),

		writerBufferSize: m.blockSizeKB << 10,
		tcpipChecksum:    m.tcpipChecksum,

		exiting: false,
		exited:  false,
		exitWg:  &sync.WaitGroup{},
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
	if tapType == 3 {
		return "tor"
	}
	if tapType >= 0 && tapType <= 30 {
		return fmt.Sprintf("isp%d", tapType)
	}
	panic(fmt.Sprintf("unsupported tap type %d", tapType))
}

func formatDuration(d time.Duration) string {
	return time.Unix(0, int64(d)).Format(TIME_FORMAT)
}

func getTempFilename(tapType zerodoc.TAPTypeEnum, mac datatype.MacInt, ip datatype.IPv4Int, firstPacketTime time.Duration, index int) string {
	return fmt.Sprintf("%s_%s_%s_%s_.%d.pcap.temp", tapTypeToString(tapType), macToString(mac), ipToString(ip), formatDuration(firstPacketTime), index)
}

func getTempFilenameByIpv6(tapType zerodoc.TAPTypeEnum, mac datatype.MacInt, ip net.IP, firstPacketTime time.Duration, index int) string {
	return fmt.Sprintf("%s_%s_%s_%s_.%d.pcap.temp", tapTypeToString(tapType), macToString(mac), ip, formatDuration(firstPacketTime), index)
}

func (w *WrappedWriter) getTempFilename(base string) string {
	if w.ip6 == nil {
		return fmt.Sprintf("%s/%d/%s", base, w.aclGID, getTempFilename(w.tapType, w.mac, w.ip, w.firstPacketTime, w.tid))
	} else {
		return fmt.Sprintf("%s/%d/%s", base, w.aclGID, getTempFilenameByIpv6(w.tapType, w.mac, w.ip6, w.firstPacketTime, w.tid))
	}
}

func (w *WrappedWriter) getFilename(base string) string {
	ipString := ""
	if w.ip6 == nil {
		ipString = ipToString(w.ip)
	} else {
		ipString = w.ip6.String()
	}
	return fmt.Sprintf("%s/%d/%s_%s_%s_%s_%s.%d.pcap", base, w.aclGID, tapTypeToString(w.tapType), macToString(w.mac), ipString, formatDuration(w.firstPacketTime), formatDuration(w.lastPacketTime), w.tid)
}

func (w *Worker) shouldCloseFile(writer *WrappedWriter, packet *datatype.MetaPacket) bool {
	// check for file size and time
	if packet.Timestamp-writer.firstPacketTime > time.Second && writer.FileSize()+int64(writer.BufferSize()) >= w.maxFileSize {
		// 距离第一个包时长超过1秒, 且大小超过maxFileSize, 则切换pcap文件
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

func (w *Worker) writePacket(packet *datatype.MetaPacket, tapType zerodoc.TAPTypeEnum, ip datatype.IPv4Int, mac datatype.MacInt, aclGID uint16) {
	key := getWriterKey(ip, aclGID, tapType)
	writer, exist := w.writers[key]
	if exist && w.shouldCloseFile(writer, packet) {
		newFilename := writer.getFilename(w.baseDirectory)
		w.finishWriter(writer, newFilename)
		delete(w.writers, key)
		exist = false
	}
	if !exist {
		writer = w.generateWrappedWriter(IpFromUint32(ip), mac, tapType, aclGID, packet.Timestamp)
		if writer == nil {
			return
		}
		w.writers[key] = writer
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

func (w *Worker) generateWrappedWriter(ip net.IP, mac datatype.MacInt, tapType zerodoc.TAPTypeEnum, aclGID uint16, timestamp time.Duration) *WrappedWriter {
	if len(w.writers) >= w.maxConcurrentFiles {
		if log.IsEnabledFor(logging.DEBUG) {
			log.Debugf("Max concurrent file (%d files) exceeded", w.maxConcurrentFiles)
		}
		w.FileRejections++
		return nil
	}

	directory := fmt.Sprintf("%s/%d", w.baseDirectory, aclGID)
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		os.MkdirAll(directory, os.ModePerm)
	}
	writer := &WrappedWriter{
		tapType:         tapType,
		aclGID:          aclGID,
		mac:             mac,
		tid:             w.index,
		firstPacketTime: timestamp,
		lastPacketTime:  timestamp,
	}
	if ip.To4() != nil {
		writer.ip = IpToUint32(ip)
	} else {
		writer.ip6 = ip
	}

	writer.tempFilename = writer.getTempFilename(w.baseDirectory)
	if log.IsEnabledFor(logging.DEBUG) {
		log.Debugf("Begin to write packets to %s", writer.tempFilename)
	}
	var err error
	if writer.Writer, err = NewWriter(writer.tempFilename, w.writerBufferSize, w.tcpipChecksum); err != nil {
		if log.IsEnabledFor(logging.DEBUG) {
			log.Debugf("Failed to create writer for %s: %s", writer.tempFilename, err)
		}
		w.FileCreationFailures++
		return nil
	}
	w.FileCreations++
	return writer
}

func (w *Worker) getWrappedWriter(ip net.IP, mac datatype.MacInt, tapType zerodoc.TAPTypeEnum, aclGID uint16, packet *datatype.MetaPacket) *WrappedWriter {
	var element *list.Element
	var result *WrappedWriter

	key := getWriterIpv6Key(ip, aclGID, tapType)
	writerList, exist := w.writersIpv6[key]
	if exist {
		for e := writerList.Front(); e != nil; e = e.Next() {
			writer := e.Value.(*WrappedWriter)
			if writer.ip6.Equal(ip) {
				element = e
				result = writer
				break
			}
		}
	} else {
		writerList = list.New()
		w.writersIpv6[key] = writerList
	}

	if result != nil && w.shouldCloseFile(result, packet) {
		newFilename := result.getFilename(w.baseDirectory)
		w.finishWriter(result, newFilename)
		writerList.Remove(element)
		result = nil
	}

	if result == nil {
		result = w.generateWrappedWriter(ip, mac, tapType, aclGID, packet.Timestamp)
		if result != nil {
			writerList.PushBack(result)
		}
	}
	return result
}

func (w *Worker) writePacketIpv6(packet *datatype.MetaPacket, tapType zerodoc.TAPTypeEnum, ip net.IP, mac datatype.MacInt, aclGID uint16) {
	writer := w.getWrappedWriter(ip, mac, tapType, aclGID, packet)
	if writer == nil {
		return
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

func (w *Worker) cleanTimeoutFile(timeNow time.Duration) {
	for key, writer := range w.writers {
		if timeNow-writer.firstPacketTime > w.maxFilePeriod {
			newFilename := writer.getFilename(w.baseDirectory)
			w.finishWriter(writer, newFilename)
			delete(w.writers, key)
		}
	}

	for _, writerList := range w.writersIpv6 {
		for e := writerList.Front(); e != nil; {
			r, writer := e, e.Value.(*WrappedWriter)
			e = e.Next()
			if timeNow-writer.firstPacketTime > w.maxFilePeriod {
				newFilename := writer.getFilename(w.baseDirectory)
				w.finishWriter(writer, newFilename)
				writerList.Remove(r)
			}
		}
	}
}

func (w *Worker) checkWriterPcap(packet *datatype.MetaPacket, direction datatype.DirectionType) zerodoc.TAPTypeEnum {
	var tapType zerodoc.TAPTypeEnum
	w.ips = w.ips[0:0]
	w.ip6s = w.ip6s[0:0]
	w.macs = w.macs[0:0]
	ipSrcCheck := packet.IpSrc != BROADCAST_IP && packet.MacSrc != BROADCAST_MAC
	ipDstCheck := packet.IpDst != BROADCAST_IP && packet.MacDst != BROADCAST_MAC
	if packet.EthType == EthernetTypeIPv6 {
		ipSrcCheck = !packet.Ip6Src.IsMulticast() && packet.MacSrc != BROADCAST_MAC
		ipDstCheck = !packet.Ip6Dst.IsMulticast() && packet.MacDst != BROADCAST_MAC
	}

	if isISP(packet.InPort) {
		tapType = zerodoc.TAPTypeEnum(packet.InPort - 0x10000)
		srcL3EpcId := packet.EndpointData.SrcInfo.L3EpcId
		ipSrcCheck = ipSrcCheck && srcL3EpcId != 0 && srcL3EpcId != datatype.EPC_FROM_INTERNET
		dstL3EpcId := packet.EndpointData.DstInfo.L3EpcId
		ipDstCheck = ipDstCheck && dstL3EpcId != 0 && dstL3EpcId != datatype.EPC_FROM_INTERNET
	} else if isTOR(packet.InPort) {
		tapType = zerodoc.ToR
		ipSrcCheck = ipSrcCheck && (packet.L2End0 || packet.EndpointData.SrcInfo.L2End)
		ipDstCheck = ipDstCheck && (packet.L2End1 || packet.EndpointData.DstInfo.L2End)
	} else {
		return 0
	}

	// 若action方向为单方向，过略掉一半的PCAP存储,
	// 若action方向为双方向且l2end都是true, 依然会存储两份流量
	if (direction&datatype.FORWARD != 0) && ipSrcCheck {
		w.ips = append(w.ips, packet.IpSrc)
		w.ip6s = append(w.ip6s, packet.Ip6Src)
		w.macs = append(w.macs, packet.MacSrc)
	}
	if (direction&datatype.BACKWARD != 0) && ipDstCheck {
		w.ips = append(w.ips, packet.IpDst)
		w.ip6s = append(w.ip6s, packet.Ip6Dst)
		w.macs = append(w.macs, packet.MacDst)
	}
	return tapType
}

func (w *Worker) Process() {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

WORKING_LOOP:
	for !w.exiting {
		n := w.packetQueue.Gets(elements)
		timeNow := time.Duration(time.Now().UnixNano())
		for _, e := range elements[:n] {
			if e == nil { // tick
				if w.exiting {
					break WORKING_LOOP
				}
				w.cleanTimeoutFile(timeNow)
				continue
			}

			block := e.(*datatype.MetaPacketBlock)
			if block.ActionFlags&datatype.ACTION_PACKET_CAPTURING == 0 {
				datatype.ReleaseMetaPacketBlock(block)
				continue
			}

			for i := uint8(0); i < block.Count; i++ {
				packet := &block.Metas[i]

				if !packet.EndpointData.Valid() { // shouldn't happen
					log.Warningf("drop invalid packet with nil EndpointData %v", packet)
					continue
				}

				for _, policy := range packet.PolicyData.AclActions {
					if policy.GetACLGID() <= 0 {
						continue
					}
					if policy.GetActionFlags()&datatype.ACTION_PACKET_CAPTURING != 0 {
						tapType := w.checkWriterPcap(packet, policy.GetDirections())
						if packet.EthType != EthernetTypeIPv6 {
							for i := range w.ips {
								w.writePacket(packet, tapType, w.ips[i], w.macs[i], policy.GetACLGID())
							}
						} else {
							for i := range w.ip6s {
								w.writePacketIpv6(packet, tapType, w.ip6s[i], w.macs[i], policy.GetACLGID())
							}
						}
					}
				}
			}

			datatype.ReleaseMetaPacketBlock(block)
		}
	}

	for _, writer := range w.writers {
		newFilename := writer.getFilename(w.baseDirectory)
		w.finishWriter(writer, newFilename)
	}
	for _, writerList := range w.writersIpv6 {
		for e := writerList.Front(); e != nil; e = e.Next() {
			writer := e.Value.(*WrappedWriter)
			newFilename := writer.getFilename(w.baseDirectory)
			w.finishWriter(writer, newFilename)
		}
	}
	log.Infof("Stopped pcap worker (%d)", w.index)
	w.exitWg.Done()
}

func (w *Worker) Close() error {
	log.Infof("Stop pcap worker (%d) writing to %d files", w.index, len(w.writers))
	w.exitWg.Add(1)
	w.exiting = true
	w.exitWg.Wait()
	w.exited = true
	return nil
}

func (w *Worker) GetCounter() interface{} {
	counter := &WorkerCounter{}
	counter, w.WorkerCounter = w.WorkerCounter, counter
	return counter
}

func (w *Worker) Closed() bool {
	return w.exited
}
