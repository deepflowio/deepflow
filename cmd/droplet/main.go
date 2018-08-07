package main

import (
	"fmt"
	"os"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"
	_ "gitlab.x.lan/yunshan/droplet-libs/monitor"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"gitlab.x.lan/yunshan/droplet/adapt"
)

var log = logging.MustGetLogger(os.Args[0])

func main() {
	InitConsoleLog()
	queue := NewOverwriteQueue("AdaptToFilter", 1000)
	trident_adapt := adapt.NewTridentAdapt(queue)
	if trident_adapt == nil {
		return
	}
	trident_adapt.Start(true)
	stats.StartStatsd()
	log.Info("It worked!")
	for {
		pkt := queue.Get()
		fmt.Println(pkt)
	}
}
