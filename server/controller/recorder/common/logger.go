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

import "fmt"

type Logger struct {
	ORGID           int
	DomainName      string
	DomainLcuuid    string
	SubDomainLcuuid string
	MsgPre          string
}

func NewLogger(orgID int) *Logger {
	return &Logger{
		ORGID:  orgID,
		MsgPre: fmt.Sprintf("org id: %d, ", orgID),
	}
}

func (l *Logger) AppendDomainName(domainName string) {
	l.DomainName = domainName
	l.MsgPre += fmt.Sprintf("domain name: %s, ", domainName)
}

func (l *Logger) AppendDomainLcuuid(domainLcuuid string) {
	l.DomainLcuuid = domainLcuuid
	l.MsgPre += fmt.Sprintf("domain lcuuid: %s, ", domainLcuuid)
}

func (l *Logger) AppendSubDomainLcuuid(subDomainLcuuid string) {
	l.SubDomainLcuuid = subDomainLcuuid
	l.MsgPre += fmt.Sprintf("sub domain lcuuid: %s, ", subDomainLcuuid)
}

func (l *Logger) AddPre(format string, a ...any) string {
	return l.MsgPre + fmt.Sprintf(format, a...)
}
