package pcap

import (
	"fmt"
	"os"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

const (
	QUEUE_BATCH_SIZE = 1024
)

type WriterKey uint64

func getWriterKey(ipInt datatype.IPv4Int, aclGID datatype.ACLID, tapType datatype.TapType) WriterKey {
	return WriterKey((uint64(ipInt) << 32) | (uint64(aclGID) << 16) | uint64(tapType))
}

type WrappedWriter struct {
	*Writer

	tapType datatype.TapType
	aclGID  datatype.ACLID
	ip      datatype.IPv4Int
	mac     datatype.MacInt

	tempFilename    string
	firstPacketTime time.Duration
	lastPacketTime  time.Duration
}

type WorkerCounter struct {
	FileCreations  uint64 `statsd:"file_creations"`
	FileCloses     uint64 `statsd:"file_closes"`
	FileRejections uint64 `statsd:"file_rejections"`
	BufferedBytes  uint64 `statsd:"buffered_bytes"`
	WrittenBytes   uint64 `statsd:"written_bytes"`
}

type Worker struct {
	inputQueue queue.MultiQueueReader
	queueKey   queue.HashKey

	maxConcurrentFiles int
	maxFileSize        int64
	maxFilePeriod      time.Duration
	baseDirectory      string

	*WorkerCounter

	writers map[WriterKey]*WrappedWriter
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

func tapTypeToString(tapType datatype.TapType) string {
	switch tapType {
	case datatype.TAP_ISP:
		return "isp"
	case datatype.TAP_TOR:
		return "tor"
	default:
		panic("unsupported tap type")
	}
}

func formatDuration(d time.Duration) string {
	return time.Unix(0, int64(d)).Format(TIME_FORMAT)
}

func (w *WrappedWriter) getTempFilename(base string) string {
	return fmt.Sprintf("%s/%d/%s_%s_%s_%s_.pcap.temp", base, w.aclGID, tapTypeToString(w.tapType), macToString(w.mac), ipToString(w.ip), formatDuration(w.firstPacketTime))
}

func (w *WrappedWriter) getFilename(base string) string {
	return fmt.Sprintf("%s/%d/%s_%s_%s_%s_%s.pcap", base, w.aclGID, tapTypeToString(w.tapType), macToString(w.mac), ipToString(w.ip), formatDuration(w.firstPacketTime), formatDuration(w.lastPacketTime))
}

func (w *Worker) shouldCloseFile(writer *WrappedWriter, packet *datatype.MetaPacket) bool {
	// check for file size and time
	if stats, err := os.Stat(writer.tempFilename); err != nil {
		log.Warningf("os.Stat() error on file %s: %s", writer.tempFilename, err)
		return true
	} else if stats.Size()+int64(writer.Size()) >= w.maxFileSize {
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
	w.BufferedBytes += counter.totalBufferedBytes
	w.WrittenBytes += counter.totalWrittenBytes
	log.Debugf("Finish writing %s, renaming to %s", writer.tempFilename, newFilename)
	os.Rename(writer.tempFilename, newFilename)
	w.FileCloses++
}

func (w *Worker) writePacket(packet *datatype.MetaPacket, tapType datatype.TapType, ip datatype.IPv4Int, mac datatype.MacInt, aclGID datatype.ACLID) {
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
			firstPacketTime: packet.Timestamp,
			lastPacketTime:  packet.Timestamp,
		}
		writer.tempFilename = writer.getTempFilename(w.baseDirectory)
		log.Debugf("Begin to write packets to %s", writer.tempFilename)
		// TODO: 池化writer（有一个[65536]byte）
		var err error
		if writer.Writer, err = NewWriter(writer.tempFilename); err != nil {
			log.Warningf("Failed to create writer for %s: %s", writer.tempFilename, err)
			return
		}
		w.writers[key] = writer
		w.FileCreations++
	}
	if err := writer.Write(packet); err != nil {
		log.Warningf("Failed to write packet to %s: %s", writer.tempFilename, err)
		return
	}
	counter := writer.GetAndResetStats()
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
			var tapType datatype.TapType
			if isISP(packet.InPort) {
				tapType = datatype.TAP_ISP
				if packet.EndpointData.SrcInfo.L3EpcId != 0 {
					ips = append(ips, packet.IpSrc)
					macs = append(macs, packet.MacSrc)
				}
				if packet.EndpointData.DstInfo.L3EpcId != 0 {
					ips = append(ips, packet.IpDst)
					macs = append(macs, packet.MacDst)
				}
			} else if isTOR(packet.InPort) {
				tapType = datatype.TAP_TOR
				if packet.EndpointData.SrcInfo.L2End {
					ips = append(ips, packet.IpSrc)
					macs = append(macs, packet.MacSrc)
				}
				if packet.EndpointData.DstInfo.L2End {
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
	log.Infof("Stop pcap worker writing to %d files", len(w.writers))
	for _, writer := range w.writers {
		newFilename := writer.getFilename(w.baseDirectory)
		w.finishWriter(writer, newFilename)
	}
	return nil
}

func (c *Worker) GetCounter() interface{} {
	counter := &WorkerCounter{}
	counter, c.WorkerCounter = c.WorkerCounter, counter
	return counter
}
