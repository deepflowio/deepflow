// +build linux

package logger

import (
	"log/syslog"
	"os"
	"path"
	"strings"

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

func EnableRsyslog(remotes ...string) error {
	rsyslogBackends = rsyslogBackends[:0]
	for _, remote := range remotes {
		if !strings.Contains(remote, ":") {
			remote += ":514"
		}
		rsyslogWriter, err := syslog.Dial("udp", remote, SYSLOG_PRIORITY, path.Base(os.Args[0]))
		if err != nil {
			return err
		}
		backend := &logging.SyslogBackend{Writer: rsyslogWriter}
		rsyslogBackends = append(rsyslogBackends, backend)
	}
	applyBackendChange()
	return nil
}
