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

package common

import (
	"context"
	"strings"
	"time"
)

type QuerierParams struct {
	Debug         string
	UseQueryCache bool
	QueryCacheTTL string
	QueryUUID     string
	DB            string
	Sql           string
	DataSource    string
	Context       context.Context
	NoPreWhere    bool
	ORGID         string
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

type EntryKey struct {
	ORGID  string
	Filter string
}

type EntryValue struct {
	Filter string
	Time   time.Time
}
