package statsd

import (
	"github.com/cactus/go-statsd-client/v5/statsd"
	"net"
	"server/controller/common"
	"server/controller/statsd/config"
	"sort"
	"time"
)

var MetaStatsd *StatsdMonitor

type StatsdMonitor struct {
	client statsd.Statter
}

func NewStatsdMonitor(cfg config.StatsdConfig) error {
	statsdServer := net.JoinHostPort(cfg.Host, cfg.Port)
	config := &statsd.ClientConfig{
		Address:       statsdServer,
		Prefix:        common.METAFLOW_STATSD_PREFIX,
		UseBuffered:   true,
		FlushInterval: time.Duration(cfg.FlushInterval),
		TagFormat:     statsd.InfixComma,
	}
	client, err := statsd.NewClientWithConfig(config)
	if err != nil {
		return err
	}
	MetaStatsd = &StatsdMonitor{
		client: client,
	}
	return nil
}

func (s *StatsdMonitor) RegisterStatsdTable(statter Statsdtable) {
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
