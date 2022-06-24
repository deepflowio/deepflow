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

	"server/controller/controller"
	"server/ingester/ingester"
	"server/querier/querier"

	logging "github.com/op/go-logging"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

var configPath = flag.String("f", "/etc/server.yaml", "Specify config file location")
var version = flag.Bool("v", false, "Display the version")

var RevCount, Revision, CommitDate, goVersion string

func main() {
	flag.Parse()
	if *version {
		fmt.Printf("%s %s %s\n%s\n", RevCount, Revision, CommitDate, goVersion)
		os.Exit(0)
	}

	go controller.Start(*configPath)
	go querier.Start(*configPath)
	closers := ingester.Start(*configPath)

	// TODO: loghandle提取出来，并增加log
	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

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
