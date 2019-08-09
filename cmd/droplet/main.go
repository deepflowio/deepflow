package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/logger"

	"gitlab.x.lan/yunshan/droplet/droplet"
	"gitlab.x.lan/yunshan/droplet/dropletctl/loglevel"
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
	logger.EnableStdoutLog()
	flag.Parse()
	if *version {
		fmt.Printf("%s-%s %s\n", RevCount, Revision, CommitDate)
		os.Exit(0)
	}

	closers := droplet.Start(*configPath)
	loglevel.NewLoglevelControl()

	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel
	log.Info("Gracefully stopping")
	wg := sync.WaitGroup{}
	wg.Add(len(closers))
	for _, closer := range closers {
		go func(c io.Closer) {
			c.Close()
			wg.Done()
		}(closer)
	}
	wg.Wait()
}
