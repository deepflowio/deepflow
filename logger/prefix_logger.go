package logger

import (
	"github.com/op/go-logging"
)

type PrefixLogger struct {
	prefix string
	log    *logging.Logger
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

func (l *PrefixLogger) Error(args ...interface{}) {
	if l.log.IsEnabledFor(logging.ERROR) {
		args = append([]interface{}{l.prefix}, args...)
		l.log.Error(args...)
	}
}

func (l *PrefixLogger) Errorf(format string, args ...interface{}) {
	if l.log.IsEnabledFor(logging.ERROR) {
		l.log.Errorf(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Warning(args ...interface{}) {
	if l.log.IsEnabledFor(logging.WARNING) {
		args = append([]interface{}{l.prefix}, args...)
		l.log.Warning(args...)
	}
}

func (l *PrefixLogger) Warningf(format string, args ...interface{}) {
	if l.log.IsEnabledFor(logging.WARNING) {
		l.log.Warningf(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Info(args ...interface{}) {
	if l.log.IsEnabledFor(logging.INFO) {
		args = append([]interface{}{l.prefix}, args...)
		l.log.Info(args...)
	}
}

func (l *PrefixLogger) Infof(format string, args ...interface{}) {
	if l.log.IsEnabledFor(logging.INFO) {
		l.log.Infof(l.prefix+" "+format, args...)
	}
}

func (l *PrefixLogger) Debug(args ...interface{}) {
	if l.log.IsEnabledFor(logging.DEBUG) {
		args = append([]interface{}{l.prefix}, args...)
		l.log.Debug(args...)
	}
}

func (l *PrefixLogger) Debugf(format string, args ...interface{}) {
	if l.log.IsEnabledFor(logging.DEBUG) {
		l.log.Debugf(l.prefix+" "+format, args...)
	}
}
