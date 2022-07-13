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
	"os"
	"strings"

	logging "github.com/op/go-logging"

	"github.com/metaflowys/metaflow/server/libs/logger"
	"github.com/metaflowys/metaflow/server/querier/querier"
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
