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

package syslog

import (
	"context"
	"strings"
	"time"

	"github.com/olivere/elastic"
)

const (
	ES_APP  = "deepflow_system_log__0_"
	ES_TYPE = "events"

	BULK_SIZE = 8192

	RECONNECT_INTERVAL = time.Minute
)

type ESLog struct {
	Timestamp uint32 `json:"timestamp"`
	Type      string `json:"type"`
	Host      string `json:"host"`
	Module    string `json:"module"`
	Severity  string `json:"severity"`
	SyslogTag string `json:"syslogtag"`
	Message   string `json:"message"`
}

type ESLogger struct {
	addresses []string
	username  string
	password  string

	client        *elastic.Client
	lastReconnect time.Time

	bulk *elastic.BulkService
}

func NewESLogger(addresses []string, username, password string) *ESLogger {
	return &ESLogger{addresses: addresses, username: username, password: password}
}

func (l *ESLogger) connect() error {
	// 第一次连上之后客户端会自动保活，不需要再处理
	urls := make([]string, 0, len(l.addresses))
	for _, a := range l.addresses {
		urls = append(urls, "http://"+a)
	}
	log.Infof("Syslog ESWriter connects to %s", strings.Join(urls, ", "))
	var err error
	l.client, err = elastic.NewClient(elastic.SetURL(urls...), elastic.SetBasicAuth(l.username, l.password))
	if err != nil {
		l.client = nil
		log.Warning("failed connecting to elasticsearch:", err)
		return err
	}
	return nil
}

func (l *ESLogger) Log(esLog *ESLog) {
	if l.client == nil {
		now := time.Now()
		if now.Sub(l.lastReconnect) < RECONNECT_INTERVAL {
			return
		}
		l.lastReconnect = now
		if l.connect() != nil {
			return
		}
	}
	if l.bulk == nil {
		l.bulk = l.client.Bulk().Type(ES_TYPE)
	}
	l.bulk.Add(elastic.NewBulkIndexRequest().Index(getIndexName(esLog.Timestamp)).Type(ES_TYPE).Doc(esLog))
	if l.bulk.NumberOfActions() >= BULK_SIZE {
		l.Flush()
	}
}

func (l *ESLogger) Flush() {
	if l.bulk == nil || l.bulk.NumberOfActions() <= 0 {
		return
	}
	resp, err := l.bulk.Do(context.TODO())
	if err != nil {
		log.Warning("batch request has error:", err)
		return
	}
	// TODO: do something with resp
	_ = resp
}

func getIndexName(timestamp uint32) string {
	return ES_APP + time.Unix(int64(timestamp), 0).Format("06010200")
}
