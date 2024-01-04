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

package stats

import (
	"flag"
	"fmt"
	"os"
	"path"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	logging "github.com/op/go-logging"
	statsd "gopkg.in/alexcesaro/statsd.v2"

	"github.com/deepflowio/deepflow/server/libs/codec"
	. "github.com/deepflowio/deepflow/server/libs/datastructure"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
)

var log = logging.MustGetLogger("stats")

var remoteType = REMOTE_TYPE_INFLUXDB

type StatSource struct {
	modulePrefix string
	module       string
	interval     time.Duration // use MinInterval when 0
	countable    Countable
	tags         OptionStatTags
	skip         int
}

func (s *StatSource) Equal(other *StatSource) bool {
	return s.module == other.module && reflect.DeepEqual(s.tags, other.tags)
}

func (s *StatSource) String() string {
	return fmt.Sprintf("%s-%v", s.module, s.tags)
}

var (
	processName       string
	processNameJoiner string = "_"
	hostname          string
	lock              sync.Mutex
	preHooks          []func()
	statSources       = LinkedList{}
	remotes           = []string{}
	dfRemote          string
	remoteIndex       = -1
	connection        client.Client

	statsdClients  = make([]*statsd.Client, 0, 2)
	dfstatsdClient *UDPClient // could be nil
)

type StatItem struct {
	Name  string
	Value interface{}
}

func registerCountable(modulePrefix, module string, countable Countable, opts ...Option) error {
	source := StatSource{modulePrefix: modulePrefix, module: module, countable: countable, tags: OptionStatTags{}}
	for _, opt := range opts {
		if tags, ok := opt.(OptionStatTags); ok { // 可能有多个
			for k, v := range tags {
				source.tags[k] = v
			}
		} else if opt, ok := opt.(OptionInterval); ok {
			source.interval = time.Duration(opt) / TICK_CYCLE * TICK_CYCLE
			if source.interval > TICK_CYCLE {
				source.skip = (60 - time.Now().Second()) / int(TICK_CYCLE/time.Second)
			}
		}
	}
	if source.tags == nil {
		source.tags = OptionStatTags{}
	}
	// if already has tag "host", add tag "_host"
	if _, ok := source.tags["host"]; ok {
		source.tags["_host"] = hostname
	} else {
		source.tags["host"] = hostname
	}
	lock.Lock()
	statSources.Remove(func(x interface{}) bool {
		closed := x.(*StatSource).countable.Closed()
		equal := x.(*StatSource).Equal(&source)
		if !closed && equal {
			log.Warningf("Possible memory leak! countable %v is not correctly closed.", &source)
		}
		return closed || equal
	})
	statSources.PushBack(&source)
	lock.Unlock()
	return nil
}

func counterToFields(counter interface{}) models.Fields {
	fields := models.Fields{}
	if items, ok := counter.([]StatItem); ok {
		for _, item := range items {
			switch item.Value.(type) {
			case uint, uint8, uint16, uint32, uint64:
				fields[item.Name] = int64(reflect.ValueOf(item.Value).Uint())
			default:
				fields[item.Name] = item.Value
			}
		}
	} else {
		val := reflect.Indirect(reflect.ValueOf(counter))
		for i := 0; i < val.Type().NumField(); i++ {
			if !val.Field(i).CanInterface() {
				continue
			}
			field := val.Type().Field(i)
			statsTag := field.Tag.Get("statsd")
			if statsTag == "" {
				continue
			}
			statsOpts := strings.Split(statsTag, ",")
			switch val.Field(i).Kind() {
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				fields[statsOpts[0]] = int64(val.Field(i).Uint())
			default:
				fields[statsOpts[0]] = val.Field(i).Interface()
			}
		}
	}
	return fields
}

func collectBatchPoints() client.BatchPoints {
	timestamp := time.Now()
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{Precision: "s"})
	lock.Lock()
	statSources.Remove(func(x interface{}) bool {
		return x.(*StatSource).countable.Closed()
	})
	for it := statSources.Iterator(); !it.Empty(); it.Next() {
		statSource := it.Value().(*StatSource)
		max := func(x, y time.Duration) time.Duration {
			if x > y {
				return x
			}
			return y
		}

		statSource.skip--
		if statSource.skip > 0 {
			continue
		}
		statSource.skip = int(max(statSource.interval, MinInterval) / TICK_CYCLE)

		fields := counterToFields(statSource.countable.GetCounter())
		point, _ := client.NewPoint(processName+processNameJoiner+statSource.modulePrefix+statSource.module, statSource.tags, fields, timestamp)
		bp.AddPoint(point)
	}
	lock.Unlock()
	return bp
}

func newStatsdClient(remote string) *statsd.Client {
	options := []statsd.Option{
		statsd.Address(remote),
		statsd.TagsFormat(statsd.InfluxDB),
	}
	c, err := statsd.New(options...)
	if err != nil {
		log.Warning(err)
		return nil
	}
	return c
}

func sendStatsd(bp client.BatchPoints) {
	encoder := new(codec.SimpleEncoder)
	if remoteType&REMOTE_TYPE_STATSD != 0 {
		for i, remote := range remotes {
			if len(statsdClients) <= i {
				statsdClients = append(statsdClients, newStatsdClient(remote))
			}
			if statsdClients[i] == nil {
				statsdClients[i] = newStatsdClient(remote)
			}
		}
	}
	if dfstatsdClient == nil && dfRemote != "" {
		dfstatsdClient, _ = NewUDPClient(UDPConfig{dfRemote, 1400})
	}

	for i, point := range bp.Points() {
		module := point.Name()
		tags := point.Tags()
		tagsOption := make([]string, 0, len(tags)*2)
		hasHost := false
		for key, value := range tags {
			if !hasHost && key == "host" {
				hasHost = true
			}
			tagsOption = append(tagsOption, key, strings.Replace(value, ":", "-", -1))
		}
		if hostname != "" && !hasHost { // specified hostname
			tagsOption = append(tagsOption, "host", hostname)
		}
		fields, _ := point.Fields()
		if remoteType&REMOTE_TYPE_STATSD != 0 {
			if len(statsdClients) > 0 {
				statsdClient := statsdClients[i%len(statsdClients)]
				if statsdClient != nil {
					statsdClient = statsdClient.Clone(
						statsd.Prefix(strings.Replace(module, "-", "_", -1)),
						statsd.Tags(tagsOption...),
					)
					for key, value := range fields {
						name := strings.Replace(key, "-", "_", -1)
						statsdClient.Count(name, value)
					}
				}
			}
		}

		if dfstatsdClient != nil {
			dfStats := pb.AcquireDFStats()
			dfStats.Timestamp = uint64(point.Time().Unix())
			dfStats.Name = strings.ReplaceAll(module, "-", "_")
			for k := range point.Tags() {
				dfStats.TagNames = append(dfStats.TagNames, k)
			}
			sort.Slice(dfStats.TagNames, func(i, j int) bool {
				return dfStats.TagNames[i] < dfStats.TagNames[j]
			})
			for _, v := range dfStats.TagNames {
				dfStats.TagValues = append(dfStats.TagValues, point.Tags()[v])
			}

			for k := range fields {
				dfStats.MetricsFloatNames = append(dfStats.MetricsFloatNames, k)
			}
			sort.Slice(dfStats.MetricsFloatNames, func(i, j int) bool {
				return dfStats.MetricsFloatNames[i] < dfStats.MetricsFloatNames[j]
			})
			for i, k := range dfStats.MetricsFloatNames {
				v := fields[k]
				var value float64
				switch v.(type) {
				case float64:
					value = v.(float64)
				case uint:
					value = float64(v.(uint))
				case uint64:
					value = float64(v.(uint64))
				case int:
					value = float64(v.(int))
				case int64:
					value = float64(v.(int64))
				}
				dfStats.MetricsFloatValues = append(dfStats.MetricsFloatValues, value)
				dfStats.MetricsFloatNames[i] = strings.Replace(k, "-", "_", -1)
			}

			if dfstatsdClient != nil {
				dfStats.Encode(encoder)
				dfstatsdClient.Write(encoder.Bytes())
				encoder.Reset()
			}
			pb.ReleaseDFStats(dfStats)
		}
	}
}

func nextRemote() error {
	remoteIndex = (remoteIndex + 1) % len(remotes)
	conn, err := client.NewUDPClient(client.UDPConfig{remotes[remoteIndex], 1400})
	if err != nil {
		return err
	}
	connection = conn
	return nil
}

func runOnce() {
	bp := collectBatchPoints()

	if len(remotes) == 0 && len(dfRemote) == 0 {
		return
	}

	if remoteType&REMOTE_TYPE_STATSD != 0 || remoteType&REMOTE_TYPE_DFSTATSD != 0 {
		sendStatsd(bp)
	}

	if remoteType&REMOTE_TYPE_INFLUXDB == 0 {
		return
	}
	for i := 0; i < len(remotes); i++ {
		if connection == nil {
			goto next_server
		}
		if err := connection.Write(bp); err != nil {
			log.Warning(err) // probably ICMP unreachable
			goto next_server
		}
		break
	next_server:
		if err := nextRemote(); err != nil {
			log.Warning(err) // probably route unreachable
		}
	}
}

func run() {
	time.Sleep(time.Second) // wait logger init

	for range time.NewTicker(TICK_CYCLE).C {
		lock.Lock()
		hooks := preHooks
		lock.Unlock()
		for _, hook := range hooks {
			hook()
		}

		if statSources.Len() > 0 {
			runOnce()
		}
	}
}

func setRemotes(addrs ...string) {
	log.Info("Remote changed to", addrs)
	remotes = addrs
	lock.Lock()
	for i := range statsdClients {
		if statsdClients[i] != nil {
			statsdClients[i].Close()
			statsdClients[i] = nil
		}
	}

	if connection != nil {
		connection.Close()
		connection = nil
	}
	lock.Unlock()
}

func setDFRemote(addr string) {
	log.Info("DFRemote changed to", addr)
	dfRemote = addr
	dfstatsdClient = nil
}

func setHostname(name string) {
	hostname = name
	lock.Lock()
	for it := statSources.Iterator(); !it.Empty(); it.Next() {
		if _, ok := it.Value().(*StatSource).tags["_host"]; ok {
			it.Value().(*StatSource).tags["_host"] = hostname
		} else {
			it.Value().(*StatSource).tags["host"] = hostname
		}
	}
	lock.Unlock()
}

func setProcessName(name string) {
	log.Info("Process name changed to", name)
	processName = name
}

func setProcessNameJoiner(joiner string) {
	log.Info("Process name joiner changed to", joiner)
	processNameJoiner = joiner
}

func winBase(path string) string {
	// Find the last element
	if i := strings.LastIndex(path, "\\"); i >= 0 {
		path = path[i+1:]
	}
	// Find the last .exe
	if i := strings.LastIndex(path, ".exe"); i >= 0 {
		path = path[:i]
	}
	// If empty now, it had only slashes.
	if path == "" {
		return "\\"
	}
	return path
}

func init() {
	if flag.Lookup("test.v") != nil {
		return
	}
	name, _ := os.Hostname()
	hostname = name
	if runtime.GOOS == "windows" {
		processName = winBase(os.Args[0])
	} else if runtime.GOOS == "linux" {
		processName = path.Base(os.Args[0])
	} else {

	}
	processName = strings.Replace(processName, "-", "_", -1)

	go run()
}
