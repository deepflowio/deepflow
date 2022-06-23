package main

import (
	"os"
	"strings"

	logging "github.com/op/go-logging"
	"server/libs/logger"

	"server/querier/querier"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

func main() {
	if os.Getppid() != 1 {
		logger.EnableStdoutLog()
	}
	logger.EnableFileLog("querier.log")
	logLevel, _ := logging.LogLevel("info")
	logging.SetLevel(logLevel, "")

	querier.Start()
}
