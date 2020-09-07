package adapter

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	_FILE_FEED        = 300 // 300秒
	_FILE_BUFFER_SIZE = 2048
)

type fileWriter struct {
	file       *os.File
	fileBuffer *bufio.Writer

	feed int
}

type syslogWriter struct {
	fileMap map[uint32]*fileWriter

	in chan *packetBuffer
}

func (w *syslogWriter) create(packet *packetBuffer) *fileWriter {
	fileName := fmt.Sprintf("/var/log/trident/%s.log", packet.tridentIp)
	file, err := os.Create(fileName)
	if err != nil {
		log.Warningf("os.Create(%s): %s\n", fileName, err)
		return nil
	}
	return &fileWriter{file, bufio.NewWriterSize(file, _FILE_BUFFER_SIZE), _FILE_FEED}
}

func (w *syslogWriter) write(writer *fileWriter, packet *packetBuffer) {
	buffer := bytes.NewBuffer(packet.buffer[datatype.MESSAGE_VALUE_OFFSET:])
	writer.fileBuffer.WriteString(buffer.String())
	writer.feed = _FILE_FEED
}

func (w *syslogWriter) run() {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case packet := <-w.in:
			hash := utils.GetIpHash(packet.tridentIp)
			writer := w.fileMap[hash]
			if writer == nil {
				writer = w.create(packet)
				w.fileMap[hash] = writer
			}

			if writer != nil {
				w.write(writer, packet)
			}
			releasePacketBuffer(packet)
		case _ = <-timer.C:
			for key, value := range w.fileMap {
				value.fileBuffer.Flush()
				value.feed--
				if value.feed == 0 {
					value.file.Close()
					delete(w.fileMap, key)
				}
			}
			timer.Reset(time.Second)
		}
	}
}

func (w *syslogWriter) decode(packet *packetBuffer) {
	w.in <- packet
}

func newSyslogWriter() *syslogWriter {
	writer := &syslogWriter{
		fileMap: make(map[uint32]*fileWriter, 8),
		in:      make(chan *packetBuffer, 1024),
	}
	go writer.run()
	return writer
}
