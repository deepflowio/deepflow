package common

import (
	"context"
	"strings"
)

type QuerierParams struct {
	Debug      string
	QueryUUID  string
	DB         string
	Sql        string
	DataSource string
	Context    context.Context
}

type TempoParams struct {
	TraceId     string
	StartTime   string
	EndTime     string
	TagName     string
	MinDuration string
	MaxDuration string
	Limit       string
	Debug       string
	Filters     []*KeyValue
	Context     context.Context
}

func (p *TempoParams) SetFilters(filterStr string) {
	if filterStr == "" {
		return
	}
	filterSplit := strings.Split(filterStr, "\" ")
	for _, filter := range filterSplit {
		if strings.Contains(filter, "=") {
			f := strings.Split(filter, "=\"")
			p.Filters = append(p.Filters, &KeyValue{
				Key:   strings.Trim(f[0], " "),
				Value: strings.Trim(f[1], "\""),
			})
		}
	}
}

type KeyValue struct {
	Key   string
	Value string
}
