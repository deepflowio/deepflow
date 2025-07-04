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

package statsd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/statsd/config"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("statsd")
var MetaStatsd *StatsdMonitor
var dfStatsdClient *stats.UDPClient

type StatsdMonitor struct {
	enable bool
	host   string
	port   int
}

func NewStatsdMonitor(cfg config.StatsdConfig) {
	MetaStatsd = &StatsdMonitor{
		enable: cfg.Enabled,
		host:   cfg.Host,
		port:   cfg.Port,
	}
	return
}

func (s *StatsdMonitor) initStatsdClient() error {
	if dfStatsdClient == nil {
		var err error
		dfStatsdClient, err = stats.NewUDPClient(stats.UDPConfig{
			Addr:        net.JoinHostPort(s.host, strconv.Itoa(s.port)),
			PayloadSize: 1400,
		})
		if err != nil {
			return fmt.Errorf("connect (%s:%d) stats udp server failed: %s", s.host, s.port, err.Error())
		}
	}
	return nil
}

func (s *StatsdMonitor) RegisterStatsdTable(stable Statsdtable) {
	if !s.enable {
		return
	}

	if err := s.initStatsdClient(); err != nil {
		log.Warning(err)
		return
	}

	encoder := new(codec.SimpleEncoder)

	statter := stable.GetStatter()
	keys := []string{}
	for key := range statter.GlobalTags {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// collect
	timeStamp := time.Now().Unix()
	dfStats := &pb.Stats{}
	for _, e := range statter.Element {
		for mfName, mfValues := range e.MetricsFloatNameToValues {
			name := e.VirtualTableName
			hostName := os.Getenv(common.NODE_NAME_KEY)
			tagNames := []string{e.PrivateTagKey, "host"}
			tagValues := []string{mfName, hostName}

			if e.UseGlobalTag {
				tagNames = append(tagNames, keys...)
				for _, k := range keys {
					tagValues = append(tagValues, statter.GlobalTags[k])
				}
			}

			metricsFloatNames := []string{}
			metricsFloatValues := []float64{}
			var vSum float64
			for _, v := range mfValues {
				vSum += v
			}
			switch e.MetricType {
			case MetricInc:
				metricsFloatNames = []string{"count"}
				metricsFloatValues = []float64{vSum}
			case MetricTiming:
				vLen := float64(len(mfValues))
				vAVG, _ := strconv.ParseFloat(fmt.Sprintf("%.3f", vSum/vLen), 64)
				metricsFloatNames = []string{"avg", "len"}
				if vLen == 1 && vAVG == 0 {
					vLen = 0
				}
				metricsFloatValues = []float64{vAVG, vLen}
			default:
				continue
			}

			dfStats.OrgId = uint32(statter.OrgID)
			dfStats.TeamId = uint32(statter.TeamID)
			dfStats.Timestamp = uint64(timeStamp)
			dfStats.Name = name
			dfStats.TagNames = tagNames
			dfStats.TagValues = tagValues
			dfStats.MetricsFloatNames = metricsFloatNames
			dfStats.MetricsFloatValues = metricsFloatValues
			dfStats.Encode(encoder)
			dfStatsdClient.Write(encoder.Bytes())
			encoder.Reset()
		}
	}
}

func (s *StatsdMonitor) Send(data *pb.Stats) error {
	if !s.enable {
		return fmt.Errorf("statsd monitor diable")
	}

	if err := s.initStatsdClient(); err != nil {
		return err
	}

	encoder := new(codec.SimpleEncoder)
	data.Encode(encoder)
	defer encoder.Reset()
	if err := dfStatsdClient.Write(encoder.Bytes()); err != nil {
		return err
	}
	return nil
}
