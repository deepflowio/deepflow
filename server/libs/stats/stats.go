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
	"strconv"
	"strings"
	"sync"
	"time"

	logging "github.com/op/go-logging"
	statsd "gopkg.in/alexcesaro/statsd.v2"

	"github.com/deepflowio/deepflow/server/libs/codec"
	. "github.com/deepflowio/deepflow/server/libs/datastructure"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("stats")
var remoteType = REMOTE_TYPE_DFSTATSD

const (
	TENANT_ORG_ID  = "tenant_org_id"
	TENANT_TEAM_ID = "tenant_team_id"
)

type StatSource struct {
	modulePrefix string
	module       string
	interval     time.Duration // use MinInterval when 0
	countable    Countable
	tags         OptionStatTags
	skip         int
	name         string
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

	statsdClients  = make([]*statsd.Client, 0, 2)
	dfstatsdClient *UDPClient // could be nil
)

type StatItem struct {
	Name  string
	Value interface{}
}

type metricPoint struct {
	name      string
	tags      map[string]string
	fields    []map[string]interface{} // one entry per struct when counter is []struct
	timestamp time.Time
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

// fieldDesc holds pre-computed metadata for a single struct field with a statsd tag.
type fieldDesc struct {
	index int
	name  string
	kind  reflect.Kind
}

// fieldDescCache maps a struct reflect.Type to its pre-computed []fieldDesc.
// Populated once per type on first call; read-mostly thereafter.
var fieldDescCache sync.Map

func getFieldDescs(t reflect.Type) []fieldDesc {
	if v, ok := fieldDescCache.Load(t); ok {
		return v.([]fieldDesc)
	}
	descs := make([]fieldDesc, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		tag := sf.Tag.Get("statsd")
		if tag == "" {
			continue
		}
		name := tag
		if idx := strings.IndexByte(tag, ','); idx >= 0 {
			name = tag[:idx]
		}
		descs = append(descs, fieldDesc{index: i, name: name, kind: sf.Type.Kind()})
	}
	fieldDescCache.Store(t, descs)
	return descs
}

func reflectStructToFields(val reflect.Value, descs []fieldDesc) map[string]interface{} {
	fields := make(map[string]interface{}, len(descs))
	for _, d := range descs {
		fv := val.Field(d.index)
		switch d.kind {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			fields[d.name] = int64(fv.Uint())
		default:
			fields[d.name] = fv.Interface()
		}
	}
	return fields
}

// counterToFields converts a counter value to a slice of field maps.
// counter may be []StatItem, a struct/pointer-to-struct, or []struct — the last
// case produces one map per element so each can be written as a separate data point.
func counterToFields(counter interface{}) []map[string]interface{} {
	if items, ok := counter.([]StatItem); ok {
		fields := make(map[string]interface{}, len(items))
		for _, item := range items {
			switch v := item.Value.(type) {
			case uint:
				fields[item.Name] = int64(v)
			case uint8:
				fields[item.Name] = int64(v)
			case uint16:
				fields[item.Name] = int64(v)
			case uint32:
				fields[item.Name] = int64(v)
			case uint64:
				fields[item.Name] = int64(v)
			default:
				fields[item.Name] = item.Value
			}
		}
		return []map[string]interface{}{fields}
	}

	val := reflect.Indirect(reflect.ValueOf(counter))
	if val.Kind() == reflect.Slice {
		n := val.Len()
		if n == 0 {
			return nil
		}
		// Dereference pointer element type (supports both []struct and []*struct).
		elemType := val.Type().Elem()
		if elemType.Kind() == reflect.Ptr {
			elemType = elemType.Elem()
		}
		descs := getFieldDescs(elemType)
		result := make([]map[string]interface{}, 0, n)
		for i := 0; i < n; i++ {
			elem := reflect.Indirect(val.Index(i)) // no-op for non-pointer elements
			if !elem.IsValid() {                   // skip nil pointers
				continue
			}
			result = append(result, reflectStructToFields(elem, descs))
		}
		if len(result) == 0 {
			return nil
		}
		return result
	}

	// single struct or pointer-to-struct (Indirect already dereffed)
	return []map[string]interface{}{reflectStructToFields(val, getFieldDescs(val.Type()))}
}

func collectPoints(timestamp time.Time) []metricPoint {
	lock.Lock()
	statSources.Remove(func(x interface{}) bool {
		return x.(*StatSource).countable.Closed()
	})
	points := make([]metricPoint, 0, statSources.Len())
	for it := statSources.Iterator(); !it.Empty(); it.Next() {
		statSource := it.Value().(*StatSource)

		statSource.skip--
		if statSource.skip > 0 {
			continue
		}
		interval := statSource.interval
		if interval < MinInterval {
			interval = MinInterval
		}
		statSource.skip = int(interval / TICK_CYCLE)
		if statSource.name == "" {
			statSource.name = processName + processNameJoiner + statSource.modulePrefix + statSource.module
		}

		counter := statSource.countable.GetCounter()
		if utils.IsNil(counter) {
			continue
		}
		points = append(points, metricPoint{
			name:      statSource.name,
			tags:      statSource.tags,
			fields:    counterToFields(counter),
			timestamp: timestamp,
		})
	}
	lock.Unlock()
	return points
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

// sortTagPairs sorts tag names and their corresponding values together by name.
// Uses insertion sort which is optimal for the small number of tags typical in metrics.
func sortTagPairs[T any](names []string, values []T) {
	n := len(names)
	for i := 1; i < n; i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func sendStatsd(points []metricPoint) {
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

	for i, p := range points {
		if remoteType&REMOTE_TYPE_STATSD != 0 && len(statsdClients) > 0 {
			tagsOption := make([]string, 0, len(p.tags)*2)
			hasHost := false
			for key, value := range p.tags {
				if !hasHost && key == "host" {
					hasHost = true
				}
				tagsOption = append(tagsOption, key, strings.ReplaceAll(value, ":", "-"))
			}
			if hostname != "" && !hasHost {
				tagsOption = append(tagsOption, "host", hostname)
			}
			statsdClient := statsdClients[i%len(statsdClients)]
			if statsdClient != nil {
				statsdClient = statsdClient.Clone(
					statsd.Prefix(strings.ReplaceAll(p.name, "-", "_")),
					statsd.Tags(tagsOption...),
				)
				for _, fm := range p.fields {
					for key, value := range fm {
						statsdClient.Count(strings.ReplaceAll(key, "-", "_"), value)
					}
				}
			}
		}

		if dfstatsdClient != nil {
			// Precompute base tags (from p.tags) once; reused for every field map.
			var orgId, teamId uint32
			baseTagNames := make([]string, 0, len(p.tags))
			baseTagValues := make([]string, 0, len(p.tags))
			for k, v := range p.tags {
				switch k {
				case TENANT_ORG_ID:
					id, _ := strconv.Atoi(v)
					orgId = uint32(id)
				case TENANT_TEAM_ID:
					id, _ := strconv.Atoi(v)
					teamId = uint32(id)
				default:
					baseTagNames = append(baseTagNames, k)
					baseTagValues = append(baseTagValues, v)
				}
			}
			sortTagPairs(baseTagNames, baseTagValues)
			name := strings.ReplaceAll(p.name, "-", "_")
			ts := uint64(p.timestamp.Unix())

			for _, fm := range p.fields {
				// Snapshot base org/team IDs; fm string fields may override per-element.
				fmOrgId := orgId
				fmTeamId := teamId

				dfStats := pb.AcquireDFStats()
				dfStats.Timestamp = ts
				dfStats.Name = name
				dfStats.TagNames = append(dfStats.TagNames, baseTagNames...)
				dfStats.TagValues = append(dfStats.TagValues, baseTagValues...)

				for k, v := range fm {
					var value float64
					isTag := false
					switch vt := v.(type) {
					case string:
						isTag = true
						if vt != "" {
							switch k {
							case TENANT_ORG_ID:
								id, _ := strconv.Atoi(vt)
								fmOrgId = uint32(id)
							case TENANT_TEAM_ID:
								id, _ := strconv.Atoi(vt)
								fmTeamId = uint32(id)
							case "host":
								rewriteHost := false
								for i := range dfStats.TagNames {
									if dfStats.TagNames[i] == "host" {
										dfStats.TagValues[i] = vt
										rewriteHost = true
										break
									}
								}
								if !rewriteHost {
									dfStats.TagNames = append(dfStats.TagNames, k)
									dfStats.TagValues = append(dfStats.TagValues, vt)
								}
							default:
								dfStats.TagNames = append(dfStats.TagNames, k)
								dfStats.TagValues = append(dfStats.TagValues, vt)
							}
						}
					case float64:
						value = vt
					case uint:
						value = float64(vt)
					case uint64:
						value = float64(vt)
					case int:
						value = float64(vt)
					case int64:
						value = float64(vt)
					}
					if !isTag {
						dfStats.MetricsFloatNames = append(dfStats.MetricsFloatNames, strings.ReplaceAll(k, "-", "_"))
						dfStats.MetricsFloatValues = append(dfStats.MetricsFloatValues, value)
					}
				}
				sortTagPairs(dfStats.MetricsFloatNames, dfStats.MetricsFloatValues)

				dfStats.OrgId = fmOrgId
				dfStats.TeamId = fmTeamId

				dfStats.Encode(encoder)
				dfstatsdClient.Write(encoder.Bytes())
				encoder.Reset()
				pb.ReleaseDFStats(dfStats)
			}
		}
	}
}

func runOnce(timestamp time.Time) {
	if len(remotes) == 0 && len(dfRemote) == 0 {
		return
	}
	sendStatsd(collectPoints(timestamp))
}

func run() {
	time.Sleep(time.Second) // wait logger init

	var lastTick int64
	for range time.NewTicker(TICK_CYCLE).C {
		lock.Lock()
		hooks := preHooks
		lock.Unlock()
		for _, hook := range hooks {
			hook()
		}

		if statSources.Len() > 0 {
			now := time.Now()
			nowTick := now.Unix() / TICK_COUNT
			// Prevent the time interval between two executions from being too small, causing two pieces of data to appear in one time period, and causing abnormal query aggregation results.
			if nowTick == lastTick {
				log.Warningf("the running interval is too short, cancel this execution. now time: %s", now)
				continue
			}

			runOnce(now)
			lastTick = nowTick
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
	processName = strings.ReplaceAll(processName, "-", "_")

	go run()
}
