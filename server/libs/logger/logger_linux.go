// +build linux

package logger

import (
	"log/syslog"
	"os"
	"path"

	"github.com/op/go-logging"
)

const (
	SYSLOG_PRIORITY = syslog.LOG_CRIT | syslog.LOG_DAEMON
)

func EnableSyslog() error {
	if syslogBackend != nil {
		return nil
	}

	syslogWriter, err := syslog.New(SYSLOG_PRIORITY, path.Base(os.Args[0]))
	if err != nil {
		return err
	}
	syslogBackend = &logging.SyslogBackend{Writer: syslogWriter}
	applyBackendChange()
	return nil
}
