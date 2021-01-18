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
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	LOG_ROTATION_INTERVAL = 24 * time.Hour       // every day
	LOG_MAX_AGE           = 365 * 24 * time.Hour // every year
	LOG_FORMAT            = "%{time:2006-01-02 15:04:05.000} [%{level:.4s}] %{shortfile} %{message}"
	LOG_COLOR_FORMAT      = "%{color}%{time:2006-01-02 15:04:05.000} [%{level:.4s}]%{color:reset} %{shortfile} %{message}"
	SYSLOG_FORMAT         = "[%{level:.4s}] %{shortfile} %{message}"
)

var (
	stdoutBackend   logging.Backend
	fileBackend     logging.Backend
	syslogBackend   logging.Backend
	rsyslogBackends []logging.Backend
	rsyslogWriters  []*RSyslogWriter
)

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
	level := logging.GetLevel("")
	logging.SetBackend(backends...)
	logging.SetLevel(level, "")
}

func getRemoteAddress(remote string) string {
	if ip := net.ParseIP(remote); ip != nil {
		// 不带端口的v4/v6地址
		if ip.To4() != nil {
			return fmt.Sprintf("%s:%d", remote, datatype.DROPLET_PORT)
		} else {
			return fmt.Sprintf("[%s]:%d", remote, datatype.DROPLET_PORT)
		}
	} else if !strings.Contains(remote, ":") {
		// 不带端口的域名
		return fmt.Sprintf("%s:%d", remote, datatype.DROPLET_PORT)
	}
	return remote
}

func EnableRsyslog(remotes ...string) error {
	rsyslogBackends = rsyslogBackends[:0]
	rsyslogWriters = rsyslogWriters[:0]
	for _, remote := range remotes {
		// 消息头包括FrameSize和Type，UDP时FrameSize无用
		header := bytes.NewBuffer([]byte{0, 0, datatype.MESSAGE_TYPE_SYSLOG})
		ioWriter := NewRsyslogWriter("udp", getRemoteAddress(remote), path.Base(os.Args[0]), header.String())
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
