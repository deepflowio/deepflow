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
	client *elastic.Client
	bulk   *elastic.BulkService
}

func NewESLogger(addresses []string, username, password string) (*ESLogger, error) {
	urls := make([]string, 0, len(addresses))
	for _, a := range addresses {
		urls = append(urls, "http://"+a)
	}
	log.Debugf("Syslog ESWriter connects to %s", strings.Join(urls, ", "))
	client, err := elastic.NewClient(elastic.SetURL(urls...), elastic.SetBasicAuth(username, password))
	if err != nil {
		return nil, err
	}
	return &ESLogger{client: client}, nil
}

func (l *ESLogger) Log(esLog *ESLog) {
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
