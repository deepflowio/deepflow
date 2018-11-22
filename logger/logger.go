package logger

import (
	"log/syslog"
	"os"
	"path"
	"strings"
	"time"

	"github.com/lestrrat/go-file-rotatelogs"
	"github.com/op/go-logging"
)

const (
	LOG_ROTATION_INTERVAL = 24 * time.Hour      // every day
	LOG_MAX_AGE           = 30 * 24 * time.Hour // every month
	LOG_FORMAT            = "%{time:2006-01-02 15:04:05.000} [%{level:.4s}] %{shortfile} %{message}"
	LOG_COLOR_FORMAT      = "%{color}%{time:2006-01-02 15:04:05.000} [%{level:.4s}]%{color:reset} %{shortfile} %{message}"
)

var (
	stdoutBackend   logging.Backend
	fileBackend     logging.Backend
	syslogBackend   logging.Backend
	rsyslogBackends []logging.Backend
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

func EnableFileLog(logPath string) error {
	dir := path.Dir(logPath)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dir, 0755)
		} else {
			return err
		}
	}

	ioWriter, err := rotatelogs.New(
		logPath+".%Y-%m-%d",
		rotatelogs.WithLinkName(logPath),
		rotatelogs.WithMaxAge(LOG_MAX_AGE),
		rotatelogs.WithRotationTime(LOG_ROTATION_INTERVAL),
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

func EnableSyslog() error {
	if syslogBackend != nil {
		return nil
	}

	processName := path.Base(os.Args[0])
	processName = processName + "/" + processName
	syslog, err := logging.NewSyslogBackend(processName)
	if err != nil {
		return err
	}
	syslogBackend = syslog
	applyBackendChange()
	return nil
}

func EnableRsyslog(remotes ...string) error {
	rsyslogBackends = rsyslogBackends[:0]
	for _, remote := range remotes {
		if !strings.Contains(remote, ":") {
			remote += ":514"
		}
		rsyslogWriter, err := syslog.Dial("udp", remote, syslog.LOG_CRIT, path.Base(os.Args[0]))
		if err != nil {
			return err
		}
		rsyslogBackends = append(rsyslogBackends, logging.NewBackendFormatter(
			logging.NewLogBackend(rsyslogWriter, "", 0),
			logging.MustStringFormatter(LOG_FORMAT),
		))
	}
	applyBackendChange()
	return nil
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
