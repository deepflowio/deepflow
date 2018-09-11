package stats

import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/op/go-logging"
	"gopkg.in/alexcesaro/statsd.v2"
)

var log = logging.MustGetLogger("stats")

var minInterval = time.Second
var remote = net.ParseIP("127.0.0.1")

const (
	STATSD_PORT = 20040
)

type StatSource struct {
	options  []statsd.Option
	interval time.Duration // use MinInterval when 0
	skip     int
}

var (
	processName  string
	lock         sync.Mutex
	statSources  map[Countable]*StatSource = make(map[Countable]*StatSource)
	statsdClient *statsd.Client
)

type StatItem struct {
	Name     string
	StatType StatType
	Value    interface{}
}

func registerCountable(module string, countable Countable, opts ...StatsOption) error {
	interval := time.Duration(0)
	options := []statsd.Option{statsd.Prefix(strings.Replace(module, "-", "_", -1))}
	for _, opt := range opts {
		if tags, ok := opt.(OptionStatTags); ok {
			tagsOption := make([]string, len(tags)*2)
			index := 0
			for key, value := range tags {
				tagsOption[index] = key
				// colon represent as start of value and unescapable in statsd
				tagsOption[index+1] = strings.Replace(value, ":", "-", -1)
				index += 2
			}
			options = append(options, statsd.Tags(tagsOption...))
		} else if opt, ok := opt.(OptionInterval); ok {
			i := time.Duration(opt)
			if time.Duration(i)%time.Second > 0 {
				msg := fmt.Sprintf("Interval must be multiple of second")
				return errors.New(msg)
			}
			interval = i
		}
	}
	statSource := &StatSource{
		options:  options,
		interval: interval,
	}
	lock.Lock()
	statSources[countable] = statSource
	lock.Unlock()
	return nil
}

func deregisterCountable(countable Countable) {
	_, ok := statSources[countable]
	if !ok {
		log.Info("Countable not registered", reflect.ValueOf(countable).String())
		return
	}
	log.Info("Deregistering countable", reflect.ValueOf(countable).String())
	lock.Lock()
	delete(statSources, countable)
	lock.Unlock()
}

func isUpper(c byte) bool {
	return 'A' <= c && c <= 'Z'
}

func sendCounter(client *statsd.Client, counter interface{}) {
	if items, ok := counter.([]StatItem); ok {
		for _, item := range items {
			statsName := strings.Replace(item.Name, "-", "_", -1)
			if item.StatType == COUNT_TYPE {
				client.Count(statsName, item.Value)
			} else { // GAUGE_TYPE
				client.Gauge(statsName, item.Value)
			}
		}
		return
	}

	val := reflect.Indirect(reflect.ValueOf(counter))
	for i := 0; i < val.Type().NumField(); i++ {
		statsName := val.Type().Field(i).Tag.Get("statsd")
		if statsName == "" {
			continue
		}
		statsName = strings.Replace(statsName, "-", "_", -1)
		memberName := val.Type().Field(i).Name
		if !isUpper(memberName[0]) { // skip private field(starting with lower case letter)
			log.Warningf("Unexported field %s with stats tag", memberName)
			continue
		}
		client.Count(statsName, val.Field(i).Interface())
	}
}

func initStatsdClient(remote net.IP) *statsd.Client {
	address := statsd.Address(fmt.Sprintf("%s:%d", remote, STATSD_PORT))
	c, err := statsd.New(address, statsd.Prefix(processName), statsd.TagsFormat(statsd.InfluxDB))
	if err != nil {
		return nil
	}
	log.Info("Statsd server connected")
	return c
}

func max(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

func run() {
	time.Sleep(time.Second) // wait logger init

	for range time.NewTicker(time.Second).C {
		if statsdClient == nil {
			statsdClient = initStatsdClient(remote)
			if statsdClient == nil {
				continue
			}
		}

		lock.Lock()
		for countable, statSource := range statSources {
			client := statsdClient.Clone(statSource.options...)
			if statSource.skip > 0 {
				statSource.skip--
				continue
			}
			counter := countable.GetCounter()
			sendCounter(client, counter)
			interval := max(statSource.interval, minInterval)
			statSource.skip = int(interval / time.Second)
		}
		lock.Unlock()
	}
}

func setMinInterval(interval time.Duration) {
	log.Infof("min interval changed to %s", interval)
	minInterval = interval
}

func setRemote(ip net.IP) {
	log.Infof("remote changed to %s", ip)
	remote = ip
	statsdClient = nil
}

func init() {
	paths := strings.Split(os.Args[0], "/")
	processName = paths[len(paths)-1]
	go run()
}
