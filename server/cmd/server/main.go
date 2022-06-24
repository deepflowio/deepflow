package main

import (
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"server/controller/controller"
	"server/ingester/ingester"
	"server/querier/querier"
)

func main() {
	go controller.Start()
	go querier.Start()
	closers := ingester.Start()

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
