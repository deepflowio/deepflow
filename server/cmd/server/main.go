/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

	"github.com/metaflowys/metaflow/server/controller/controller"
	"github.com/metaflowys/metaflow/server/ingester/ingester"
	"github.com/metaflowys/metaflow/server/querier/querier"

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
		fmt.Printf(
			"%s %s %s\n%s\n%s\n",
			RevCount, Revision, CommitDate,
			"metaflow-server community edition",
			goVersion,
		)
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
