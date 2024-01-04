/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package syslog

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	BUFSIZE = 4096
)

type DailyRotateWriter struct {
	filename string
	fp       *os.File
	bw       *bufio.Writer
}

func NewRotateWriter(filename string) *DailyRotateWriter {
	return &DailyRotateWriter{filename: filename}
}

func (w *DailyRotateWriter) logFilename(t time.Time) string {
	return w.filename + "." + t.Format("2006-01-02")
}

func (w *DailyRotateWriter) ensureLogFile() error {
	// 调用前确保filename没打开
	now := time.Now()
	nowFilename := w.logFilename(now)
	// check file
	if fs, err := os.Lstat(w.filename); !os.IsNotExist(err) {
		if err != nil {
			log.Warningf("os.Stat() failed, try removing: %v", w.filename, err)
			if err = os.Remove(w.filename); err != nil {
				log.Warningf("os.Remove() %s failed: %v", w.filename, err)
				return err
			}
		}
		if fs.Mode()&os.ModeSymlink != 0 {
			// 如果log文件是symbolic link，检查连接到的目标是正确的日志文件
			linked, err := os.Readlink(w.filename)
			if err != nil {
				log.Warningf("os.Readlink() failed, try removing: %v", w.filename, err)
				if err = os.Remove(w.filename); err != nil {
					log.Warningf("os.Remove() %s failed: %v", w.filename, err)
					return err
				}
			} else if linked == nowFilename {
				// 理想，链接到的文件是今天的
				return nil
			} else {
				// 删掉并压缩
				if err = os.Remove(w.filename); err != nil {
					log.Warningf("os.Remove() %s failed: %v", w.filename, err)
					return err
				}
				if err = compressLogFile(linked); err != nil {
					log.Warningf("compress %s failed: %v", linked, err)
					return err
				}
				if err = os.Remove(linked); err != nil {
					log.Warningf("remove %s failed: %v", linked, err)
				}
			}
		} else {
			// 如果是个文本，改名字
			if err = os.Rename(w.filename, nowFilename); err != nil {
				log.Warningf("os.Rename() %s failed: %v", w.filename, err)
				return err
			}
		}
	}
	if err := os.Symlink(nowFilename, w.filename); err != nil {
		log.Warningf("os.Symlink() %s failed: %v", w.filename, err)
		return err
	}
	return nil
}

func (w *DailyRotateWriter) checkLogFile() bool {
	linked, err := os.Readlink(w.filename)
	return err == nil && linked == w.logFilename(time.Now())
}

func compressLogFile(filename string) error {
	// 先关闭文件再调用这个
	iFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer iFile.Close()

	gzFilename := filename + ".gz"
	oFile, err := os.Create(gzFilename)
	if err != nil {
		return err
	}
	defer oFile.Close()

	bufWriter := bufio.NewWriterSize(oFile, _FILE_BUFFER_SIZE)
	writer := gzip.NewWriter(bufWriter)
	buffer := make([]byte, BUFSIZE)
	for {
		n, err := iFile.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		if m, err := writer.Write(buffer[:n]); err != nil {
			return err
		} else if m != n {
			return fmt.Errorf("%d of %d bytes written", m, n)
		}
	}
	writer.Close()
	return bufWriter.Flush()
}

func (w *DailyRotateWriter) Write(p []byte) (n int, err error) {
	if w.fp == nil {
		if err = w.ensureLogFile(); err != nil {
			return 0, err
		}
		w.fp, err = os.OpenFile(w.filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return 0, err
		}
		w.bw = bufio.NewWriterSize(w.fp, _FILE_BUFFER_SIZE)
	}
	return w.bw.Write(p)
}

func (w *DailyRotateWriter) Flush() error {
	if w.fp == nil {
		return nil
	}
	w.bw.Flush()
	w.fp.Sync()
	if !w.checkLogFile() {
		w.bw = nil
		w.fp.Close()
		w.fp = nil
		return w.ensureLogFile()
	}
	return nil
}

func (w *DailyRotateWriter) Close() error {
	if w.fp == nil {
		return nil
	}
	w.bw.Flush()
	w.bw = nil
	w.fp.Close()
	w.fp = nil
	return nil
}

var _ io.Writer = &DailyRotateWriter{}
