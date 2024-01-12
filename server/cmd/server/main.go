/*
 * Copyright (c) 2024 Yunshan Networks
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
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/deepflowio/deepflow/server/common"
	"github.com/deepflowio/deepflow/server/controller/controller"
	"github.com/deepflowio/deepflow/server/controller/report"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/ingester/droplet/profiler"
	"github.com/deepflowio/deepflow/server/ingester/ingester"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/querier/querier"

	logging "github.com/op/go-logging"
)

func execName() string {
	splitted := strings.Split(os.Args[0], "/")
	return splitted[len(splitted)-1]
}

var log = logging.MustGetLogger(execName())

const (
	PROFILER_PORT = 9526
)

var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
var configPath = flagSet.String("f", "/etc/server.yaml", "Specify config file location")
var version = flagSet.Bool("v", false, "Display the version")

var Branch, RevCount, Revision, CommitDate, goVersion, CompileTime string

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

	log.Infof("deepflow-server config: %+v", *cfg)

	debug.SetIpAndPort(ingesterctl.DEBUG_LISTEN_IP, ingesterctl.DEBUG_LISTEN_PORT)
	debug.NewLogLevelControl()
	profiler := profiler.NewProfiler(PROFILER_PORT)
	if cfg.Profiler {
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		profiler.Start()
	}

	if cfg.MaxCPUs > 0 {
		runtime.GOMAXPROCS(cfg.MaxCPUs)
	}

	startContinuousProfile(&cfg.ContinuousProfile)

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

	common.NewMonitor(cfg.MonitorPaths)

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
