package main

import (
	"os"
	"os/signal"
	"syscall"

	"server/controller/controller"
	"server/querier/querier"
)

func main() {
	go controller.Start()
	go querier.Start()

	// TODO: loghandle提取出来，并增加log
	// setup system signal
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel
}
