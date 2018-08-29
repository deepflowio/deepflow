package stats

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/op/go-logging"
	. "gopkg.in/alexcesaro/statsd.v2"
)

var log = logging.MustGetLogger("stats")

const (
	STATSD_PORT = 20040
)

type StatSource struct {
	prefixOption Option
	tagsOption   Option
	statsdClient *Client
}

var (
	processName  string
	lock         sync.Mutex
	statSources  map[Countable]*StatSource = make(map[Countable]*StatSource)
	statsdClient *Client
)

type StatType uint8

const (
	COUNT_TYPE StatType = iota
	GAUGE_TYPE
)

type StatItem struct {
	Name     string
	StatType StatType
	Value    interface{}
}

type StatTags map[string]string

var (
	EMPTY_TAG = StatTags{}
)

func (t *StatTags) String() string {
	if len(*t) == 0 {
		return "{}"
	}
	var strBuf bytes.Buffer
	strBuf.WriteString("{")
	for key, value := range *t {
		strBuf.WriteString(key + ": " + value + ", ")
	}
	strBuf.Truncate(strBuf.Len() - 2)
	return strBuf.String() + "}"
}

type Countable interface {
	// needs to be thread-safe, clear is required after read
	// accept struct or []StatItem
	GetCounter() interface{}
}

func RegisterCountable(module string, tags StatTags, countable Countable) {
	tagsOption := make([]string, len(tags)*2)
	index := 0
	for key, value := range tags {
		tagsOption[index] = key
		// colon represent as start of value and unescapable in statsd
		tagsOption[index+1] = strings.Replace(value, ":", "-", -1)
		index += 2
	}
	statSource := &StatSource{
		prefixOption: Prefix(strings.Replace(module, "-", "_", -1)),
		tagsOption:   Tags(tagsOption...),
	}
	lock.Lock()
	statSources[countable] = statSource
	lock.Unlock()
}

func DeregisterCountable(countable Countable) {
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

func sendCounter(statSource *StatSource, counter interface{}) {
	if statsdClient != nil {
		statSource.statsdClient = statsdClient.Clone(statSource.prefixOption, statSource.tagsOption)
	} else {
		return
	}

	if items, ok := counter.([]StatItem); ok {
		for _, item := range items {
			statsName := strings.Replace(item.Name, "-", "_", -1)
			if item.StatType == COUNT_TYPE {
				statSource.statsdClient.Count(statsName, item.Value)
			} else { // GAUGE_TYPE
				statSource.statsdClient.Gauge(statsName, item.Value)
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
		statSource.statsdClient.Count(statsName, val.Field(i).Interface())
	}
}

func initStatsdClient(remote net.IP) *Client {
	address := Address(fmt.Sprintf("%s:%d", remote, STATSD_PORT))
	c, err := New(address, Prefix(processName), TagsFormat(InfluxDB))
	if err != nil {
		return nil
	}
	log.Info("Statsd server connected")
	return c
}

func run(remote net.IP, interval time.Duration) {
	time.Sleep(time.Second) // wait logger init
	statsdClient = initStatsdClient(remote)

	ticker := time.NewTicker(interval)
	for range ticker.C {
		lock.Lock()
		for countable, statSource := range statSources {
			counter := countable.GetCounter()
			sendCounter(statSource, counter)
		}
		lock.Unlock()

		if statsdClient == nil {
			statsdClient = initStatsdClient(remote)
		}
	}
}

func StartStatsd(remote net.IP, interval time.Duration) {
	paths := strings.Split(os.Args[0], "/")
	processName = paths[len(paths)-1]
	go run(remote, interval)
}
