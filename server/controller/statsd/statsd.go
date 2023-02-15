/*
 * Copyright (c) 2022 Yunshan Networks
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

package statsd

import (
	"net"
	"sort"
	"time"

	"github.com/cactus/go-statsd-client/v5/statsd"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/statsd/config"
)

var MetaStatsd *StatsdMonitor

type StatsdMonitor struct {
	enable bool
	client statsd.Statter
}

func NewStatsdMonitor(cfg config.StatsdConfig) error {
	if !cfg.Enabled {
		MetaStatsd = &StatsdMonitor{
			enable: cfg.Enabled,
		}
		return nil
	}

	statsdServer := net.JoinHostPort(cfg.Host, cfg.Port)
	config := &statsd.ClientConfig{
		Address:       statsdServer,
		Prefix:        common.DEEPFLOW_STATSD_PREFIX,
		UseBuffered:   true,
		FlushInterval: time.Duration(cfg.FlushInterval),
		TagFormat:     statsd.InfixComma,
	}
	client, err := statsd.NewClientWithConfig(config)
	if err != nil {
		return err
	}
	MetaStatsd = &StatsdMonitor{
		enable: cfg.Enabled,
		client: client,
	}
	return nil
}

func (s *StatsdMonitor) RegisterStatsdTable(statter Statsdtable) {
	if !s.enable {
		return
	}

	gTags := []statsd.Tag{}
	keys := []string{}
	for key := range statter.GetStatter().GlobalTags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		gTags = append(gTags, statsd.Tag{k, statter.GetStatter().GlobalTags[k]})
	}
	// collect
	for _, e := range statter.GetStatter().Element {
		rate := e.Rate
		if rate == 0 {
			rate = 1.0
		}
		for tagValue, values := range e.PrivateTagValueToCount {
			tags := []statsd.Tag{{e.PrivateTagKey, tagValue}}
			if e.UseGlobalTag {
				tags = append(tags, gTags...)
			}
			switch e.MetricType {
			case "Inc":
				for _, value := range values {
					s.client.Inc(e.MetricName, int64(value), rate, tags...)
				}
			case "Timing":
				for _, value := range values {
					s.client.Timing(e.MetricName, int64(value), rate, tags...)
				}
			}
		}
	}
}
