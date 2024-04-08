/**
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

package common

import (
	"fmt"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("recorder.common")

type Logger struct {
	ORGID         int
	DomainName    string
	SubDomainName string
	MsgPre        string
}

func NewLogger(orgID int) *Logger {
	return &Logger{
		ORGID:  orgID,
		MsgPre: fmt.Sprintf("oid: %d, ", orgID),
	}
}

func (l *Logger) InitMsgPre() {
	if l.ORGID != 0 {
		l.MsgPre = fmt.Sprintf("oid: %d, ", l.ORGID)
	}
	if l.DomainName != "" {
		l.MsgPre += fmt.Sprintf("dn: %s, ", l.DomainName)
	}
	if l.SubDomainName != "" {
		l.MsgPre += fmt.Sprintf("sdn: %s, ", l.SubDomainName)
	}
}

func (l *Logger) SetDomainName(n string) {
	l.DomainName = n
	l.InitMsgPre()
}

func (l *Logger) SetSubDomainName(n string) {
	l.SubDomainName = n
	l.InitMsgPre()
}

func (l *Logger) GetMsgPre() string {
	return l.MsgPre
}

func (l *Logger) AddPre(format string, a ...any) string {
	return l.MsgPre + fmt.Sprintf(format, a...)
}

func (l *Logger) Copy() *Logger {
	return &Logger{
		ORGID:         l.ORGID,
		DomainName:    l.DomainName,
		SubDomainName: l.SubDomainName,
		MsgPre:        l.MsgPre,
	}
}
