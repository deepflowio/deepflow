package main

import (
	"os"

	"github.com/op/go-logging"

	. "gitlab.x.lan/yunshan/droplet-libs/logger"
)

var log = logging.MustGetLogger(os.Args[0])

func main() {
	InitConsoleLog()
	log.Info("It worked!")
}
