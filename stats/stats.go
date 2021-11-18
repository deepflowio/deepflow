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
	"unsafe"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	logging "github.com/op/go-logging"
	statsd "gopkg.in/alexcesaro/statsd.v2"

	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	. "gitlab.yunshan.net/yunshan/droplet-libs/datastructure"
)

var log = logging.MustGetLogger("stats")

var remoteType = REMOTE_TYPE_INFLUXDB

type StatSource struct {
	module    string
	interval  time.Duration // use MinInterval when 0
	countable Countable
	tags      OptionStatTags
	skip      int
}

func (s *StatSource) Equal(other *StatSource) bool {
	return s.module == other.module && reflect.DeepEqual(s.tags, other.tags)
}

func (s *StatSource) String() string {
	return fmt.Sprintf("%s-%v", s.module, s.tags)
}

var (
	processName string
	hostname    string
	lock        sync.Mutex
	preHooks    []func()
	statSources = LinkedList{}
	remotes     = []string{}
	dfRemote    string
	remoteIndex = -1
	connection  client.Client

	statsdClients  = make([]*statsd.Client, 2) // could be nil
	dfstatsdClient *UDPClient                  // could be nil
)

type StatItem struct {
	Name  string
	Value interface{}
}

func registerCountable(module string, countable Countable, opts ...Option) error {
	source := StatSource{module: module, countable: countable, tags: OptionStatTags{}}
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
	source.tags["host"] = hostname
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
		point, _ := client.NewPoint(processName+"."+statSource.module, statSource.tags, fields, timestamp)
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
	for i, remote := range remotes {
		if len(statsdClients) <= i {
			statsdClients = append(statsdClients, newStatsdClient(remote))
		}
		if statsdClients[i] == nil {
			statsdClients[i] = newStatsdClient(remote)
		}
	}
	if dfstatsdClient == nil && dfRemote != "" {
		dfstatsdClient, _ = NewUDPClient(UDPConfig{dfRemote, 1400})
	}

	for _, point := range bp.Points() {
		module := point.Name()
		tags := point.Tags()
		tagsOption := make([]string, 0, len(tags)*2)
		for key, value := range tags {
			tagsOption = append(tagsOption, key, strings.Replace(value, ":", "-", -1))
		}
		if hostname != "" { // specified hostname
			tagsOption = append(tagsOption, "host", hostname)
		}
		fields, _ := point.Fields()
		for _, statsdClient := range statsdClients {
			if statsdClient == nil {
				continue
			}
			statsdClient = statsdClient.Clone(
				statsd.Prefix(strings.Replace(module, "-", "_", -1)),
				statsd.Tags(tagsOption...),
			)
			for key, value := range fields {
				name := strings.Replace(key, "-", "_", -1)
				statsdClient.Count(name, value)
			}
		}

		if dfstatsdClient != nil {
			dfStats := AcquireDFStats()
			dfStats.Time = uint32(point.Time().Unix())
			module = strings.ReplaceAll(module, ".", "_")
			dfStats.TableName = strings.ReplaceAll(module, "-", "_")
			for k, v := range point.Tags() {
				dfStats.Tags = append(dfStats.Tags, Tag{k, v})
			}
			sort.Slice(dfStats.Tags, func(i, j int) bool {
				return dfStats.Tags[i].Key < dfStats.Tags[j].Key
			})

			for k, v := range fields {
				name := strings.Replace(k, "-", "_", -1)
				valueType := TypeInt64
				var value int64
				switch v.(type) {
				case float64:
					valueType = TypeFloat64
					vfloat := v.(float64)
					value = *((*int64)(unsafe.Pointer(&vfloat)))
				default:
					value = v.(int64)
				}
				dfStats.Fields = append(dfStats.Fields, Field{name, valueType, value})
			}
			sort.Slice(dfStats.Fields, func(i, j int) bool {
				return dfStats.Fields[i].Key < dfStats.Fields[j].Key
			})

			if dfstatsdClient != nil {
				dfStats.Encode(encoder)
				dfstatsdClient.Write(encoder.Bytes())
				encoder.Reset()
			}
			ReleaseDFStats(dfStats)
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

	if len(remotes) == 0 {
		return
	}

	// FIXME: deprecated statsd
	if remoteType == REMOTE_TYPE_STATSD {
		sendStatsd(bp)
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
		it.Value().(*StatSource).tags["host"] = hostname
	}
	lock.Unlock()
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

	go run()
}
