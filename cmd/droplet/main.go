package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"

	"gitlab.x.lan/yunshan/droplet/droplet"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

var configPath = flag.String("f", "/etc/droplet.yaml", "Specify config file location")
var version = flag.Bool("v", false, "Display the version")

var RevCount, Revision, CommitDate string

func main() {
	InitConsoleLog("info")
	flag.Parse()
	if *version {
		fmt.Printf("%s-%s %s\n", RevCount, Revision, CommitDate)
		os.Exit(0)
	}

	closers := droplet.Start(*configPath)

	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	for {
		sig := <-signalChannel
		if sig == os.Interrupt {
			for _, closer := range closers {
				go closer.Close()
			}
			log.Info("Gracefully stopping")
			break
		}
	}
}
