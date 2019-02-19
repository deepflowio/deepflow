package stats

import (
	"flag"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	"github.com/op/go-logging"
	"gopkg.in/alexcesaro/statsd.v2"

	. "gitlab.x.lan/yunshan/droplet-libs/datastructure"
)

var log = logging.MustGetLogger("stats")

const STATSD_PORT = 20040

var remoteType = REMOTE_TYPE_INFLUXDB

type StatSource struct {
	module    string
	interval  time.Duration // use MinInterval when 0
	countable Countable
	tags      OptionStatTags
	skip      int
}

var (
	processName string
	hostname    string
	lock        sync.Mutex
	preHooks    []func()
	statSources = LinkedList{}
	remotes     = []net.UDPAddr{}
	remoteIndex = -1
	connection  client.Client

	statsdClients = make([]*statsd.Client, 1) // could be nil
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
			source.interval = time.Duration(opt) / time.Second * time.Second
			if source.interval > time.Second {
				source.skip = 60 - time.Now().Second()
			}
		}
	}
	if source.tags == nil {
		source.tags = OptionStatTags{}
	}
	source.tags["host"] = hostname
	lock.Lock()
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
	for it := statSources.Iterator(); !it.Empty(); it.Next() {
		statSource := it.Value().(*StatSource)
		for statSource.countable.Closed() {
			statSources.Remove(&it)
			statSource = it.Value().(*StatSource)
		}

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
		statSource.skip = int(max(statSource.interval, MinInterval) / time.Second)

		fields := counterToFields(statSource.countable.GetCounter())
		point, _ := client.NewPoint(processName+"."+statSource.module, statSource.tags, fields, timestamp)
		bp.AddPoint(point)
	}
	lock.Unlock()
	return bp
}

func newStatsdClient(remote net.UDPAddr) *statsd.Client {
	options := []statsd.Option{
		statsd.Address(remote.String()),
		statsd.TagsFormat(statsd.InfluxDB),
	}
	if hostname != "" { // specified hostname
		options = append(options, statsd.Tags("host", hostname))
	}
	c, err := statsd.New(options...)
	if err != nil {
		log.Warning(err)
		return nil
	}
	return c
}

func sendStatsd(bp client.BatchPoints) {
	for i, remote := range remotes {
		if statsdClients[i] == nil {
			statsdClients[i] = newStatsdClient(net.UDPAddr{remote.IP, STATSD_PORT, ""})
		}
	}

	for _, point := range bp.Points() {
		module := point.Name()
		tags := point.Tags()
		tagsOption := make([]string, 0, len(tags)*2)
		for key, value := range tags {
			tagsOption = append(tagsOption, key, strings.Replace(value, ":", "-", -1))
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
	}
}

func nextRemote() error {
	remoteIndex = (remoteIndex + 1) % len(remotes)
	conn, err := client.NewUDPClient(client.UDPConfig{remotes[remoteIndex].String(), 1400})
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

	for range time.NewTicker(time.Second).C {
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

func setRemotes(addrs ...net.UDPAddr) {
	log.Info("Remote changed to", addrs)
	remotes = addrs
	lock.Lock()
	if connection != nil {
		connection.Close()
		connection = nil
	}
	lock.Unlock()
}

func setHostname(name string) {
	hostname = name
	lock.Lock()
	for it := statSources.Iterator(); !it.Empty(); it.Next() {
		it.Value().(*StatSource).tags["host"] = hostname
	}
	lock.Unlock()
}

func init() {
	if flag.Lookup("test.v") != nil {
		return
	}
	name, _ := os.Hostname()
	hostname = name
	processName = path.Base(os.Args[0])
	go run()
}
