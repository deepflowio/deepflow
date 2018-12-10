package pcap

import (
	"fmt"
	"os"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	BUFSIZE = 65536
	SNAPLEN = 65535
)

type WriterCounter struct {
	totalBufferedBytes uint64
	totalWrittenBytes  uint64
}

type Writer struct {
	filename string
	fp       *os.File

	buffer []byte
	offset int

	fileSize int64

	WriterCounter
}

func NewWriter(filename string) (*Writer, error) {
	writer := &Writer{buffer: make([]byte, BUFSIZE)}
	if err := writer.init(filename); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *Writer) init(filename string) error {
	w.filename = filename
	isNewFile := false
	if stat, err := os.Stat(filename); os.IsNotExist(err) {
		isNewFile = true
	} else if err == nil {
		if stat.Size() == 0 {
			isNewFile = true
		}
	} else {
		return err
	}
	w.offset = 0
	var err error
	if isNewFile {
		if w.fp, err = os.Create(filename); err != nil {
			return err
		}
		NewGlobalHeader(w.buffer, SNAPLEN)
		w.offset = GLOBAL_HEADER_LEN
		w.totalBufferedBytes += GLOBAL_HEADER_LEN
	} else {
		if w.fp, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) Write(packet *datatype.MetaPacket) error {
	header := NewRecordHeader(w.buffer[w.offset:])
	w.offset += RECORD_HEADER_LEN
	size := NewRawPacket(w.buffer[w.offset:]).MetaPacketToRaw(packet)
	w.offset += size
	header.SetTimestamp(packet.Timestamp)
	header.SetOrigLen(int(packet.PacketLen))
	header.SetInclLen(size)
	w.totalBufferedBytes += uint64(RECORD_HEADER_LEN + size)
	if BUFSIZE-w.offset < RECORD_HEADER_LEN+MAX_PACKET_LEN {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) BufferSize() int {
	return w.offset
}

func (w *Writer) FileSize() int64 {
	return w.fileSize
}

func (w *Writer) GetStats() WriterCounter {
	return w.WriterCounter
}

func (w *Writer) ResetStats() {
	w.totalBufferedBytes = 0
	w.totalWrittenBytes = 0
}

func (w *Writer) GetAndResetStats() WriterCounter {
	c := w.GetStats()
	w.ResetStats()
	return c
}

func (w *Writer) Close() error {
	if err := w.Flush(); err != nil {
		return err
	}
	return w.fp.Close()
}

func (w *Writer) Clear() {
	w.offset = 0
}

func (w *Writer) Flush() error {
	if w.offset == 0 {
		return nil
	}
	if n, err := w.fp.Write(w.buffer[:w.offset]); err != nil {
		return err
	} else {
		w.fileSize += int64(n)
		w.totalWrittenBytes += uint64(n)
		if n != w.offset {
			return fmt.Errorf("Flush(): not all bytes written to file %s", w.filename)
		}
	}
	w.Clear()
	return nil
}
