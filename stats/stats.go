package stats

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/op/go-logging"
	"gopkg.in/alexcesaro/statsd.v2"
)

var log = logging.MustGetLogger("stats")

const (
	STATSD_PORT = 20040
)

type StatSource struct {
	options  []statsd.Option
	interval time.Duration // use MinInterval when 0
	skip     int
}

var (
	processName   string
	hostname      string
	lock          sync.Mutex
	preHooks      []func()
	statSources   = make(map[Countable]*StatSource)
	remotes       = []net.IP{net.ParseIP("127.0.0.1")}
	statsdClients = make([]*statsd.Client, 1) // could be nil
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
			tagsOption := make([]string, 0, len(tags)*2+2)
			for key, value := range tags {
				// colon represent as start of value and unescapable in statsd
				tagsOption = append(tagsOption, key, strings.Replace(value, ":", "-", -1))
			}
			options = append(options, statsd.Tags(tagsOption...))
		} else if opt, ok := opt.(OptionInterval); ok {
			i := time.Duration(opt)
			if i%time.Second > 0 {
				msg := fmt.Sprintf("Interval must be multiple of second")
				return errors.New(msg)
			}
			interval = i
		}
	}
	statSource := &StatSource{options: options, interval: interval}
	lock.Lock()
	statSources[countable] = statSource
	lock.Unlock()
	return nil
}

func deregisterCountable(countable Countable) {
	lock.Lock()
	defer lock.Unlock()
	_, ok := statSources[countable]
	if !ok {
		log.Warning("Countable not registered", reflect.ValueOf(countable).String())
		return
	}
	log.Debug("Deregistering countable", reflect.ValueOf(countable).String())
	delete(statSources, countable)
}

func isUpper(c byte) bool {
	return 'A' <= c && c <= 'Z'
}

func sendCounter(client *statsd.Client, counter interface{}) {
	if items, ok := counter.([]StatItem); ok {
		for _, item := range items {
			statsName := strings.Replace(item.Name, "-", "_", -1)
			client.Count(statsName, item.Value)
		}
		return
	}

	val := reflect.Indirect(reflect.ValueOf(counter))
	for i := 0; i < val.Type().NumField(); i++ {
		field := val.Type().Field(i)
		statsTag := field.Tag.Get("statsd")
		if statsTag == "" {
			continue
		}
		if !isUpper(field.Name[0]) { // skip private field(starting with lower case letter)
			log.Warningf("Unexported field %s with stats tag", field.Name)
			continue
		}
		statsOpts := strings.Split(statsTag, ",")
		name := strings.Replace(statsOpts[0], "-", "_", -1)
		value := val.Field(i).Interface()
		client.Count(name, value)
	}
}

func newStatsdClient(remote net.IP) *statsd.Client {
	options := []statsd.Option{
		statsd.Address(fmt.Sprintf("%s:%d", remote, STATSD_PORT)),
		statsd.Prefix(processName),
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
	log.Info("Statsd server connected")
	return c
}

func max(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

func runOnce() {
	lock.Lock()
	hooks := preHooks
	lock.Unlock()
	for _, hook := range hooks {
		hook()
	}

	lock.Lock()
	for i, remote := range remotes {
		if statsdClients[i] == nil {
			statsdClients[i] = newStatsdClient(remote)
		}
	}

	for countable, statSource := range statSources {
		statSource.skip--
		if statSource.skip > 0 {
			continue
		}
		counter := countable.GetCounter()
		for _, statsdClient := range statsdClients {
			if statsdClient == nil {
				continue
			}
			client := statsdClient.Clone(statSource.options...)
			sendCounter(client, counter)
		}
		interval := max(statSource.interval, MinInterval)
		statSource.skip = int(interval / time.Second)
	}
	lock.Unlock()
}

func run() {
	time.Sleep(time.Second) // wait logger init

	for range time.NewTicker(time.Second).C {
		runOnce()
	}
}

func resetClients() {
	lock.Lock()
	for _, c := range statsdClients {
		if c != nil {
			c.Close()
		}
	}
	statsdClients = make([]*statsd.Client, len(remotes))
	lock.Unlock()
}

func setRemotes(ips ...net.IP) {
	log.Infof("Remote changed to %s", ips)
	remotes = ips
	resetClients()
}

func setHostname(name string) {
	hostname = name
	resetClients()
}

func init() {
	if flag.Lookup("test.v") != nil {
		return
	}
	processName = path.Base(os.Args[0])
	go run()
}
