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
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	logging "github.com/op/go-logging"
)

const (
	LOG_ROTATION_INTERVAL = 24 * time.Hour       // every day
	LOG_MAX_AGE           = 365 * 24 * time.Hour // every year
	LOG_FORMAT            = "%{time:2006-01-02 15:04:05.000} [%{level:.4s}] [%{module}] %{shortfile} %{message}"
	LOG_COLOR_FORMAT      = "%{color}%{time:2006-01-02 15:04:05.000} [%{level:.4s}]%{color:reset} [%{module}] %{shortfile} %{message}"
	SYSLOG_FORMAT         = "[%{level:.4s}] %{shortfile} %{message}"
)

var (
	stdoutBackend   logging.Backend
	fileBackend     logging.Backend
	syslogBackend   logging.Backend
	rsyslogBackends []logging.Backend
	rsyslogWriters  []*RSyslogWriter
	customBackends  []ClosableBackend
)

type ClosableBackend interface {
	logging.Backend
	io.Closer
}

func EnableStdoutLog() {
	if stdoutBackend != nil {
		return
	}
	stdoutBackend = logging.NewBackendFormatter(
		logging.NewLogBackend(os.Stdout, "", 0),
		logging.MustStringFormatter(LOG_COLOR_FORMAT),
	)
	applyBackendChange()
}

func compressFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}

	gzfile, err := os.OpenFile(filename+".gz", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		file.Close()
		return err
	}
	defer gzfile.Close()

	gzWriter := gzip.NewWriter(gzfile)
	defer gzWriter.Close()

	if _, err := io.Copy(gzWriter, file); err != nil {
		file.Close()
		return err // probably disk full
	}
	file.Close()

	os.Remove(filename)
	return nil
}

func EnableFileLogWithMaxAge(logPath string, maxAge time.Duration) error {
	dir := path.Dir(logPath)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dir, 0755)
		} else {
			return err
		}
	}

	rotationHandler := rotatelogs.HandlerFunc(func(e rotatelogs.Event) {
		if e.Type() != rotatelogs.FileRotatedEventType {
			return
		}
		filename := e.(*rotatelogs.FileRotatedEvent).PreviousFile()
		if err := compressFile(filename); err != nil {
			os.Remove(filename + ".gz")
		}
	})
	ioWriter, err := rotatelogs.New(
		logPath+".%Y-%m-%d",
		rotatelogs.WithLinkName(logPath),
		rotatelogs.WithMaxAge(maxAge),
		rotatelogs.WithRotationTime(LOG_ROTATION_INTERVAL),
		rotatelogs.WithHandler(rotationHandler),
	)
	if err != nil {
		return err
	}

	fileBackend = logging.NewBackendFormatter(
		logging.NewLogBackend(ioWriter, "", 0),
		logging.MustStringFormatter(LOG_FORMAT),
	)
	applyBackendChange()
	return nil
}

func EnableFileLog(logPath string) error {
	return EnableFileLogWithMaxAge(logPath, LOG_MAX_AGE)
}

func EnableCustomBackends(backends ...ClosableBackend) {
	for _, b := range customBackends {
		b.Close()
	}
	customBackends = append(customBackends[:0], backends...)
	applyBackendChange()
}

func applyBackendChange() {
	var backends []logging.Backend
	if stdoutBackend != nil {
		backends = append(backends, stdoutBackend)
	}
	if fileBackend != nil {
		backends = append(backends, fileBackend)
	}
	if syslogBackend != nil {
		backends = append(backends, syslogBackend)
	}
	backends = append(backends, rsyslogBackends...)
	for _, b := range customBackends {
		backends = append(backends, b)
	}
	level := logging.GetLevel("")
	logging.SetBackend(backends...)
	logging.SetLevel(level, "")
}

func getRemoteAddress(remote string, port int) string {
	if ip := net.ParseIP(remote); ip != nil {
		// 不带端口的v4/v6地址
		if ip.To4() != nil {
			return fmt.Sprintf("%s:%d", remote, port)
		} else {
			return fmt.Sprintf("[%s]:%d", remote, port)
		}
	} else if !strings.Contains(remote, ":") {
		// 不带端口的域名
		return fmt.Sprintf("%s:%d", remote, port)
	}
	return remote
}

// msgType在datatype/droplet-message.go中定义
// trident调用时前2个参数传入datatype.MESSAGE_TYPE_SYSLOG 和 30033
func EnableRsyslog(msgType byte, remotePort int, remotes ...string) error {
	rsyslogBackends = rsyslogBackends[:0]
	rsyslogWriters = rsyslogWriters[:0]
	for _, remote := range remotes {
		// 消息头包括FrameSize和Type，UDP时FrameSize无用
		header := bytes.NewBuffer([]byte{0, 0, 0, 0, msgType})
		ioWriter := NewRsyslogWriter("udp", getRemoteAddress(remote, remotePort), path.Base(os.Args[0]), header.String())
		rsyslogWriters = append(rsyslogWriters, ioWriter)

		backend := logging.NewBackendFormatter(
			logging.NewLogBackend(ioWriter, "", 0),
			logging.MustStringFormatter(SYSLOG_FORMAT),
		)
		rsyslogBackends = append(rsyslogBackends, backend)
	}
	applyBackendChange()
	return nil
}

func RsyslogSetThreshold(value uint32) {
	for _, w := range rsyslogWriters {
		w.SetThreshold(value)
	}
}

func RsyslogSetHostname(value string) {
	for _, w := range rsyslogWriters {
		w.SetHostname(value)
	}
}
