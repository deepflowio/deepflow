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
	"github.com/op/go-logging"
)

type PrefixLogger struct {
	prefix string
	*logging.Logger
}

// 将logger包装为前缀logger
// 注意需要自行将ExtraCalldepth加1，以便拿到log文件名，行号等信息
func WrapWithPrefixLogger(prefix string, logger *logging.Logger) *PrefixLogger {
	return &PrefixLogger{prefix, logger}
}

func GetPrefixLogger(module, prefix string) (*PrefixLogger, error) {
	logger, err := logging.GetLogger(module)
	if err != nil {
		return nil, err
	}
	logger.ExtraCalldepth++
	return &PrefixLogger{prefix, logger}, nil
}

func (l *PrefixLogger) GetPrefix() string {
	return l.prefix
}

func (l *PrefixLogger) UpdatePrefix(prefix string) {
	l.prefix = prefix
}

func (l *PrefixLogger) Error(args ...interface{}) {
	if l.IsEnabledFor(logging.ERROR) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Error(args...)
	}
}

func (l *PrefixLogger) Errorf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.ERROR) {
		l.Logger.Errorf(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Warning(args ...interface{}) {
	if l.IsEnabledFor(logging.WARNING) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Warning(args...)
	}
}

func (l *PrefixLogger) Warningf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.WARNING) {
		l.Logger.Warningf(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Notice(args ...interface{}) {
	if l.IsEnabledFor(logging.NOTICE) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Notice(args...)
	}
}

func (l *PrefixLogger) Noticef(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.NOTICE) {
		l.Logger.Noticef(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Info(args ...interface{}) {
	if l.IsEnabledFor(logging.INFO) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Info(args...)
	}
}

func (l *PrefixLogger) Infof(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.INFO) {
		l.Logger.Infof(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Debug(args ...interface{}) {
	if l.IsEnabledFor(logging.DEBUG) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Debug(args...)
	}
}

func (l *PrefixLogger) Debugf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.DEBUG) {
		l.Logger.Debugf(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Fatal(args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Fatal(args...)
	}
}

func (l *PrefixLogger) Fatalf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		l.Logger.Fatalf(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Panic(args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Panic(args...)
	}
}

func (l *PrefixLogger) Panicf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		l.Logger.Panicf(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Critical(args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		args = append([]interface{}{l.prefix}, args...)
		l.Logger.Critical(args...)
	}
}

func (l *PrefixLogger) Criticalf(format string, args ...interface{}) {
	if l.IsEnabledFor(logging.CRITICAL) {
		l.Logger.Criticalf(l.prefix+" "+format, args...)
	}
}
