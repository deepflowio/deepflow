package main

import (
	"fmt"
	"os"

	"gitlab.x.lan/yunshan/droplet/adapt"
	"gitlab.x.lan/yunshan/droplet/handler"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"
)

var log = logging.MustGetLogger(os.Args[0])

func main() {
	InitConsoleLog()
	ch := make(chan handler.MetaPktHdr, 100)
	trident_adapt := (&adapt.TridentAdapt{}).Init(nil, ch)
	trident_adapt.Start(true)
	log.Info("It worked!")
	for {
		pkt := <-ch
		fmt.Println(pkt.String())
	}
}
