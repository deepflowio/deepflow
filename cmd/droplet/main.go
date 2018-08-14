package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"
	_ "gitlab.x.lan/yunshan/droplet-libs/monitor"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/flowgen"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/mapreduce"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

var configFile = flag.String("f", "/etc/droplet.yaml", "Specify config file location")

func main() {
	InitConsoleLog()
	filterqueue := NewOverwriteQueue("AdapterToFilter", 1000)
	tridentAdapter := adapter.NewTridentAdapter(filterqueue)
	if tridentAdapter == nil {
		return
	}

	flowqueue := NewOverwriteQueue("FilterToFlow", 1000)
	cfg := config.Load(*configFile)
	laber := labeler.NewLabelerManager(cfg, filterqueue, flowqueue)
	laber.Start()

	flowAppOutputQueue := NewOverwriteQueue("flowAppOutputQueue", 1000)
	flowGenerator := flowgen.New(flowqueue, flowAppOutputQueue, 60)
	if flowGenerator == nil {
		return
	}
	stats.StartStatsd()
	flowGenerator.Start()
	tridentAdapter.Start(true)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for {
			taggedFlow := flowAppOutputQueue.(Queue).Get().(*TaggedFlow)
			fmt.Println(flowgen.TaggedFlowString(taggedFlow))
			(&mapreduce.MapProcessor{}).FlowHandler(taggedFlow)
		}
	}()
	log.Info("It worked!")
	wg.Wait()
}
