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
	"strings"

	"github.com/op/go-logging"
)

var argsJoiner = " "

// Logger is a wrapper around go-logging.Logger.
// It adds support for logging with flexible prefixes. Prefixes should implement the Prefix interface.
// The Logger will automatically extract the prefixes from the arguments and prepend them to the log message ordered by the order of the arguments.
// Prefixes must be placed at the end of the arguments list.
// Example:
//
//	// logger is a *Logger, ORGPrefix is the struct which implements Prefix interface and returns the organization ID information.
//	logger.Info("message", &ORGPrefix{2})
//
//	will log: "[ORGID-2] message"
type Logger struct {
	*logging.Logger
}

func MustGetLogger(module string) *Logger {
	l := logging.MustGetLogger(module)
	l.ExtraCalldepth++
	return &Logger{l}
}

func (l *Logger) splitArgs(args ...interface{}) (trueArgs []interface{}, prefixes string) {
	for _, arg := range args {
		if prefix, ok := arg.(Prefix); ok {
			if prefix.Prefix() != "" {
				prefixes += prefix.Prefix() + argsJoiner
			}
		} else if prefix, ok := arg.([]Prefix); ok {
			for _, p := range prefix {
				if p.Prefix() != "" {
					prefixes += p.Prefix() + argsJoiner
				}
			}
		} else {
			trueArgs = append(trueArgs, arg)
		}
	}
	return
}

func (l *Logger) formatArgs(args ...interface{}) []interface{} {
	args, prefixes := l.splitArgs(args...)
	if prefixes != "" {
		args = append([]interface{}{strings.Trim(prefixes, argsJoiner)}, args...)
	}
	return args
}

func (l *Logger) formatFArgs(fmt string, args ...interface{}) (string, []interface{}) {
	args, prefixes := l.splitArgs(args...)
	if prefixes != "" {
		fmt = prefixes + fmt
	}
	return fmt, args
}

func (l *Logger) Error(args ...interface{}) {
	if l.IsEnabledFor(logging.ERROR) {
		l.Logger.Error(l.formatArgs(args...)...)
	}
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.ERROR) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Errorf(format, args...)
	}
}

func (l *Logger) Warning(args ...interface{}) {
	if l.IsEnabledFor(logging.WARNING) {
		l.Logger.Warning(l.formatArgs(args...)...)
	}
}

func (l *Logger) Warningf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.WARNING) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Warningf(format, args...)
	}
}

func (l *Logger) Notice(args ...interface{}) {
	if l.IsEnabledFor(logging.NOTICE) {
		l.Logger.Notice(l.formatArgs(args...)...)
	}
}

func (l *Logger) Noticef(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.NOTICE) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Noticef(format, args...)
	}
}

func (l *Logger) Info(args ...interface{}) {
	if l.IsEnabledFor(logging.INFO) {
		l.Logger.Info(l.formatArgs(args...)...)
	}
}

func (l *Logger) Infof(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.INFO) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Infof(format, args...)
	}
}

func (l *Logger) Debug(args ...interface{}) {
	if l.IsEnabledFor(logging.DEBUG) {
		l.Logger.Debug(l.formatArgs(args...)...)
	}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.DEBUG) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Debugf(format, args...)
	}
}

func (l *Logger) Fatal(args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		l.Logger.Fatal(l.formatArgs(args...)...)
	}
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Fatalf(format, args...)
	}
}

func (l *Logger) Panic(args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		l.Logger.Panic(l.formatArgs(args...)...)
	}
}

func (l *Logger) Panicf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Panicf(format, args...)
	}
}

func (l *Logger) Critical(args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		l.Logger.Critical(l.formatArgs(args...)...)
	}
}

func (l *Logger) Criticalf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		format, args := l.formatFArgs(format, args...)
		l.Logger.Criticalf(format, args...)
	}
}
