//go:build linux
// +build linux

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
