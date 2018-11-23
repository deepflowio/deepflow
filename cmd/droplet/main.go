package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"

	"gitlab.x.lan/yunshan/droplet/droplet"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
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
	dropletctl.NewLoglevelControl()

	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	for {
		sig := <-signalChannel
		if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			log.Info("Gracefully stopping")
			wg := sync.WaitGroup{}
			wg.Add(len(closers))
			for _, closer := range closers {
				go func() {
					closer.Close()
					wg.Done()
				}()
			}
			wg.Wait()
			break
		}
	}
}
