package stats

import (
	"bytes"
	"fmt"
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
	lock         sync.Mutex
	statSources  map[Countable]*StatSource = make(map[Countable]*StatSource)
	statsdClient *Client
)

type StatType uint8
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

const (
	RETRIEVE_INTERVAL = 10 * time.Second
)

type Countable interface {
	// thread-safe
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
		prefixOption: Prefix(module),
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

	val := reflect.Indirect(reflect.ValueOf(counter))
	for i := 0; i < val.Type().NumField(); i++ {
		statsName := val.Type().Field(i).Tag.Get("statsd")
		if statsName == "" {
			continue
		}
		memberName := val.Type().Field(i).Name
		if !isUpper(memberName[0]) { // skip private field(starting with lower case letter)
			log.Warningf("Unexported field %s with stats tag", memberName)
			continue
		}
		statSource.statsdClient.Count(statsName, val.Field(i).Interface())
	}
}

func initStatsdClient() *Client {
	c, err := New(Address(fmt.Sprintf(":%d", STATSD_PORT)),
		Prefix(os.Args[0]), TagsFormat(InfluxDB))
	if err != nil {
		return nil
	}
	log.Info("Statsd server connected")
	return c
}

func run() {
	time.Sleep(time.Second) // wait logger init
	statsdClient = initStatsdClient()

	ticker := time.NewTicker(RETRIEVE_INTERVAL)
	for range ticker.C {
		lock.Lock()
		for countable, statSource := range statSources {
			counter := countable.GetCounter()
			sendCounter(statSource, counter)
		}
		lock.Unlock()

		if statsdClient == nil {
			statsdClient = initStatsdClient()
		}
	}
}

func StartStatsd() {
	go run()
}
