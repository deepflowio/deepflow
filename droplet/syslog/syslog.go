package syslog

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	logging "github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

var log = logging.MustGetLogger("droplet.syslog")

const (
	_FILE_FEED        = 3600 // 3600秒
	_FILE_BUFFER_SIZE = 2048
	QUEUE_BATCH_SIZE  = 1024
)

type fileWriter struct {
	file       *os.File
	fileBuffer *bufio.Writer

	feed int
}

type syslogWriter struct {
	index   int
	fileMap map[uint32]*fileWriter
	in      queue.QueueReader
}

func (w *syslogWriter) create(packet *receiver.RecvBuffer) *fileWriter {
	fileName := fmt.Sprintf("/var/log/trident/%s.log", packet.IP)
	file, err := os.Create(fileName)
	if err != nil {
		log.Warningf("os.Create(%s): %s\n", fileName, err)
		return nil
	}
	return &fileWriter{file, bufio.NewWriterSize(file, _FILE_BUFFER_SIZE), _FILE_FEED}
}

func (w *syslogWriter) write(writer *fileWriter, packet *receiver.RecvBuffer) {
	if packet.End > packet.Begin {
		buffer := bytes.NewBuffer(packet.Buffer[packet.Begin:packet.End])
		writer.fileBuffer.WriteString(buffer.String())
		writer.feed = _FILE_FEED
	}
}

func NewSyslogWriter(in queue.QueueReader) *syslogWriter {
	writer := &syslogWriter{
		fileMap: make(map[uint32]*fileWriter, 8),
		in:      in,
	}

	go writer.run()
	return writer
}

func (w *syslogWriter) run() {
	packets := make([]interface{}, QUEUE_BATCH_SIZE)

	for {
		n := w.in.Gets(packets)
		for i := 0; i < n; i++ {
			value := packets[i]
			if packet, ok := value.(*receiver.RecvBuffer); ok {
				hash := utils.GetIpHash(packet.IP)
				writer := w.fileMap[hash]
				if writer == nil {
					writer = w.create(packet)
					w.fileMap[hash] = writer
				}

				if writer != nil {
					w.write(writer, packet)
				}
				receiver.ReleaseRecvBuffer(packet)
			} else if value == nil { // flush ticker
				for key, value := range w.fileMap {
					value.fileBuffer.Flush()
					value.feed--
					if value.feed == 0 {
						value.file.Close()
						delete(w.fileMap, key)
					}
				}
			} else {
				log.Warning("get queue data type wrong")
			}
		}
	}
}
