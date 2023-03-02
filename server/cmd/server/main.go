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

	"io/ioutil"

	"github.com/deepflowio/deepflow/server/common"
	"github.com/deepflowio/deepflow/server/controller/controller"
	"github.com/deepflowio/deepflow/server/controller/report"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/ingester/ingester"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/querier/querier"

	yaml "gopkg.in/yaml.v2"

	logging "github.com/op/go-logging"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
var configPath = flagSet.String("f", "/etc/server.yaml", "Specify config file location")
var version = flagSet.Bool("v", false, "Display the version")

var Branch, RevCount, Revision, CommitDate, goVersion, CompileTime string

type Config struct {
	LogFile  string `default:"/var/log/deepflow/server.log" yaml:"log-file"`
	LogLevel string `default:"info" yaml:"log-level"`
}

func loadConfig(path string) *Config {
	config := &Config{}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("Read config file path: %s, error: %s", err, path)
		os.Exit(1)
	}

	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		fmt.Printf("Unmarshal yaml(%s) error: %s", path, err)
		os.Exit(1)
	}
	return config
}

func main() {
	flagSet.Parse(os.Args[1:])
	if *version {
		fmt.Printf(
			"%s\n%s\n%s\n%s\n%s\n%s\n",
			"Name: deepflow-server community edition",
			"Branch: "+Branch,
			"CommitID: "+Revision,
			"RevCount: "+RevCount,
			"Compiler: "+goVersion,
			"CompileTime: "+CompileTime,
		)
		os.Exit(0)
	}

	cfg := loadConfig(*configPath)
	logger.EnableStdoutLog()
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")

	ctx, cancel := utils.NewWaitGroupCtx()
	defer func() {
		cancel()
		utils.GetWaitGroupInCtx(ctx).Wait() // wait for goroutine cancel
	}()

	report.SetServerInfo(Branch, RevCount, Revision)

	shared := common.NewControllerIngesterShared()

	go controller.Start(ctx, *configPath, cfg.LogFile, shared)

	go querier.Start(*configPath, cfg.LogFile)
	closers := ingester.Start(*configPath, shared)

	common.NewMonitor()

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
