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

package logger

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type RSyslogWriter struct {
	tag       string
	hostname  string
	network   string
	raddr     string
	header    string
	infoMutex sync.RWMutex

	mu   sync.Mutex // guards conn
	conn net.Conn

	threshold  uint32
	count      uint32
	timeInHour int
}

func (w *RSyslogWriter) connect() (err error) {
	if w.conn != nil {
		// ignore err from close, it makes sense to continue anyway
		w.conn.Close()
		w.conn = nil
	}

	if w.network != "" {
		var c net.Conn
		c, err = net.Dial(w.network, w.raddr)
		if err == nil {
			w.conn = c
			w.infoMutex.RLock()
			if w.hostname == "" {
				w.infoMutex.RUnlock()
				w.infoMutex.Lock()
				w.hostname = c.LocalAddr().String()
				w.infoMutex.Unlock()
			} else {
				w.infoMutex.RUnlock()
			}
		}
	}
	return
}

// Close closes a connection to the syslog daemon.
func (w *RSyslogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		err := w.Close()
		w.conn = nil
		return err
	}
	return nil
}

// Write sends a log message to the syslog daemon.
func (w *RSyslogWriter) Write(b []byte) (int, error) {
	if w.threshold == 0 {
		return w.writeAndRetry(string(b))
	}

	nowInHour := time.Now().Hour()
	if w.timeInHour != nowInHour {
		w.timeInHour = nowInHour
		if w.count > w.threshold {
			w.writeAndRetry(fmt.Sprintf("[WARN] Log threshold is exceeded, lost %d logs.", w.count-w.threshold))
		}
		w.count = 0
	}

	if w.count > w.threshold {
		w.count++
		return len(b), nil
	}
	context := string(b)
	if w.count == w.threshold {
		context = fmt.Sprintf("[WARN] Log threshold is exceeded, current config is %d.", w.threshold)
	}
	n, err := w.writeAndRetry(context)
	if err == nil {
		w.count++
	}
	return n, err
}

func (w *RSyslogWriter) writeAndRetry(s string) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		if n, err := w.write(s); err == nil {
			return n, err
		}
	}
	if err := w.connect(); err != nil {
		return 0, err
	}
	return w.write(s)
}

func (w *RSyslogWriter) write(msg string) (int, error) {
	// ensure it ends in a \n
	nl := ""
	if !strings.HasSuffix(msg, "\n") {
		nl = "\n"
	}

	w.infoMutex.RLock()
	hostname := w.hostname
	w.infoMutex.RUnlock()

	err := w.writeString(hostname, w.tag, msg, nl)
	if err != nil {
		return 0, err
	}
	// Note: return the length of the input, not the number of
	// bytes printed by Fprintf, because this must behave like
	// an io.Writer.
	return len(msg), nil
}

func (w *RSyslogWriter) writeString(hostname, tag, msg, nl string) error {
	timestamp := time.Now().Format(time.RFC3339)
	_, err := fmt.Fprintf(w.conn, "%s%s %s %s[%d]: %s%s", w.header,
		timestamp, hostname,
		tag, os.Getpid(), msg, nl)
	return err
}

func (w *RSyslogWriter) SetThreshold(value uint32) {
	w.threshold = value
}

func (w *RSyslogWriter) SetHostname(value string) {
	w.infoMutex.Lock()
	w.hostname = value
	w.infoMutex.Unlock()
}

func NewRsyslogWriter(network, raddr string, tag, header string) *RSyslogWriter {
	if tag == "" {
		tag = os.Args[0]
	}
	hostname, _ := os.Hostname()

	w := &RSyslogWriter{
		tag:      tag,
		hostname: hostname,
		network:  network,
		raddr:    raddr,
		header:   header,
	}
	return w
}
