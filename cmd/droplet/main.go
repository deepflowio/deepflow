package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"
	_ "gitlab.x.lan/yunshan/droplet-libs/monitor"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/adapt"
	"gitlab.x.lan/yunshan/droplet/flowgen"
)

var log = logging.MustGetLogger(os.Args[0])

func main() {
	InitConsoleLog()
	queue := NewOverwriteQueue("AdaptToFilter", 1000)
	trident_adapt := adapt.NewTridentAdapt(queue)
	if trident_adapt == nil {
		return
	}
	flowAppOutputQueue := NewOverwriteQueue("flowAppOutputQueue", 1000)
	flowGenerator := flowgen.New(queue, flowAppOutputQueue, 60)
	if flowGenerator == nil {
		return
	}
	stats.StartStatsd()
	flowGenerator.Start()
	trident_adapt.Start(true)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for {
			taggedFlow := flowAppOutputQueue.Get().(*TaggedFlow)
			fmt.Println(flowgen.TaggedFlowString(taggedFlow))
		}
	}()
	log.Info("It worked!")
	wg.Wait()
}
