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
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/statsd/config"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("statsd")
var MetaStatsd *StatsdMonitor
var dfstatsdClient *stats.UDPClient

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

func (s *StatsdMonitor) RegisterStatsdTable(statter Statsdtable) {
	if !s.enable {
		return
	}

	if dfstatsdClient == nil {
		var err error
		dfstatsdClient, err = stats.NewUDPClient(stats.UDPConfig{fmt.Sprintf("%s:%d", s.host, s.port), 1400})
		if err != nil {
			log.Warningf("connect (%s:%d) stats udp server failed: %s", s.host, s.port, err.Error())
			return
		}
	}

	encoder := new(codec.SimpleEncoder)

	keys := []string{}
	for key := range statter.GetStatter().GlobalTags {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// collect
	timeStamp := time.Now().Unix()
	for _, e := range statter.GetStatter().Element {
		for mfName, mfValues := range e.MetricsFloatNameToValues {
			name := common.DEEPFLOW_STATSD_PREFIX + "_" + e.VirtualTableName
			hostName := os.Getenv(common.NODE_NAME_KEY)
			tagNames := []string{e.PrivateTagKey, "host"}
			tagValues := []string{mfName, hostName}

			if e.UseGlobalTag {
				tagNames = append(tagNames, keys...)
				for _, k := range keys {
					tagValues = append(tagValues, statter.GetStatter().GlobalTags[k])
				}
			}

			metricsFloatNames := []string{}
			metricsFloatValues := []float64{}
			var vSum int
			for _, v := range mfValues {
				vSum += v
			}
			switch e.MetricType {
			case "Inc":
				metricsFloatNames = []string{"count"}
				metricsFloatValues = []float64{float64(vSum)}
			case "Timing":
				vLen := len(mfValues)
				vAVG := math.Ceil(float64(vSum / vLen))
				metricsFloatNames = []string{"avg", "len"}
				if vLen == 1 && vAVG == 0 {
					vLen = 0
				}
				metricsFloatValues = []float64{vAVG, float64(vLen)}
			default:
				continue
			}

			dfStats := pb.AcquireDFStats()
			dfStats.Timestamp = uint64(timeStamp)
			dfStats.Name = name
			dfStats.TagNames = tagNames
			dfStats.TagValues = tagValues
			dfStats.MetricsFloatNames = metricsFloatNames
			dfStats.MetricsFloatValues = metricsFloatValues
			dfStats.Encode(encoder)
			dfstatsdClient.Write(encoder.Bytes())
			encoder.Reset()
		}
	}
}
