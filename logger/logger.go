package logger

import (
	"os"
	"path"
	"time"

	"log/syslog"

	"github.com/lestrrat/go-file-rotatelogs"
	"github.com/op/go-logging"
)

const (
	LOG_ROTATION_INTERVAL = 24 * time.Hour      // every day
	LOG_MAX_AGE           = 30 * 24 * time.Hour // every month
	LOG_FORMAT            = "%{time:2006-01-02 15:04:05.000} [%{level:.4s}] %{shortfile} %{message}"
	LOG_COLOR_FORMAT      = "%{color}%{time:2006-01-02 15:04:05.000} [%{level:.4s}]%{color:reset} %{shortfile} %{message}"
)

var log = logging.MustGetLogger(path.Base(os.Args[0]))

type StdoutLog string
type FileLog string
type Rsyslog string
type SyslogLog string

func Stdout() StdoutLog {
	return ""
}

func Syslog() SyslogLog {
	return ""
}

func stdoutBackend(level logging.Level) logging.Backend {
	stdout := logging.AddModuleLevel(
		logging.NewBackendFormatter(
			logging.NewLogBackend(os.Stdout, "", 0),
			logging.MustStringFormatter(LOG_COLOR_FORMAT),
		),
	)
	stdout.SetLevel(level, "")
	return stdout
}

func fileBackend(level logging.Level, logPath string) logging.Backend {
	dir := path.Dir(logPath)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dir, 0755)
		} else {
			log.Error(err.Error())
		}
	}

	ioWriter, err := rotatelogs.New(
		logPath+".%Y-%m-%d",
		rotatelogs.WithLinkName(logPath),
		rotatelogs.WithMaxAge(LOG_MAX_AGE),
		rotatelogs.WithRotationTime(LOG_ROTATION_INTERVAL),
	)
	if err != nil {
		log.Error(err.Error())
		os.Exit(-1)
	}

	file := logging.AddModuleLevel(
		logging.NewBackendFormatter(
			logging.NewLogBackend(ioWriter, "", 0),
			logging.MustStringFormatter(LOG_FORMAT),
		),
	)
	file.SetLevel(level, "")
	return file
}

func logLevelToPriority(level logging.Level) syslog.Priority {
	switch level {
	case logging.CRITICAL:
		return syslog.LOG_CRIT
	case logging.ERROR:
		return syslog.LOG_ERR
	case logging.WARNING:
		return syslog.LOG_WARNING
	case logging.NOTICE:
		return syslog.LOG_NOTICE
	case logging.INFO:
		return syslog.LOG_INFO
	case logging.DEBUG:
		return syslog.LOG_DEBUG
	default:
		panic("invalid type")
	}
}

func syslogBackend(level logging.Level) logging.Backend {
	processName := path.Base(os.Args[0])
	processName = processName + "/" + processName
	syslogBackend, err := logging.NewSyslogBackendPriority(processName, logLevelToPriority(level)|syslog.LOG_LOCAL2)
	if err != nil {
		log.Error(err.Error())
		os.Exit(-1)
	}
	syslog := logging.AddModuleLevel(syslogBackend)
	syslog.SetLevel(level, "")
	return syslog
}

func rsyslogWriter(level logging.Level, remote string) (logging.Backend, error) {
	rsyslogWriter, err := syslog.Dial("udp", remote, logLevelToPriority(level), path.Base(os.Args[0]))
	if err != nil {
		return nil, err
	}
	rsyslog := logging.AddModuleLevel(
		logging.NewBackendFormatter(
			logging.NewLogBackend(rsyslogWriter, "", 0),
			logging.MustStringFormatter(LOG_FORMAT),
		),
	)
	rsyslog.SetLevel(level, "")
	return rsyslog, nil
}

func InitLog(levelString string, loggers ...interface{}) error {
	level, err := logging.LogLevel(levelString)
	if err != nil {
		return err
	}

	backends := make([]logging.Backend, 0, len(loggers))
	for _, logger := range loggers {
		switch logger.(type) {
		case StdoutLog:
			backends = append(backends, stdoutBackend(level))
		case FileLog:
			backends = append(backends, fileBackend(level, (string)(logger.(FileLog))))
		case SyslogLog:
			backends = append(backends, syslogBackend(level))
		case Rsyslog:
			rsyslog, err := rsyslogWriter(level, (string)(logger.(Rsyslog)))
			if err != nil {
				return err
			}
			backends = append(backends, rsyslog)
		default:
			continue
		}
	}
	logging.SetBackend(backends...)
	return nil
}
