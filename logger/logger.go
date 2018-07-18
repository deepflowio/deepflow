package logger

import (
	"os"
	"path"
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

var log = logging.MustGetLogger(os.Args[0])

func InitConsoleLog() {
	stdout := logging.NewBackendFormatter(
		logging.NewLogBackend(os.Stdout, "", 0),
		logging.MustStringFormatter(LOG_COLOR_FORMAT),
	)
	logging.SetBackend(stdout)
}

func InitLog(filePath string, levelString string) {
	level, err := logging.LogLevel(levelString)
	if err != nil {
		log.Error(err.Error())
		os.Exit(-1)
	}

	stdout := logging.AddModuleLevel(
		logging.NewBackendFormatter(
			logging.NewLogBackend(os.Stdout, "", 0),
			logging.MustStringFormatter(LOG_COLOR_FORMAT),
		),
	)
	stdout.SetLevel(level, "")

	dir := path.Dir(filePath)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dir, 0755)
		} else {
			log.Error(err.Error())
		}
	}

	ioWriter, err := rotatelogs.New(
		filePath+".%Y-%m-%d",
		rotatelogs.WithLinkName(filePath),
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
	logging.SetBackend(stdout, file)
}
