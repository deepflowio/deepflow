/**
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

package diffbase

import (
	"fmt"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("recorder.cache.diffbase")

func addDiffBase(resource string, detail interface{}) string {
	return fmt.Sprintf("%s (detail: %+v) success", common.LogAdd(resource), detail)
}

func updateDiffBase(resource string, detail interface{}) string {
	return fmt.Sprintf("%s (detail: %+v) success", common.LogUpdate(resource), detail)
}

func deleteDiffBase(resource, lcuuid string) string {
	return fmt.Sprintf("%s (lcuuid: %s) success", common.LogDelete(resource), lcuuid)
}

type LogController struct {
	// controll log level, set info when triggered by resource change event, set debug when called by timing cache refresh
	level logging.Level
}

func (l *LogController) SetLogLevel(level logging.Level) error {
	if level != logging.DEBUG && level != logging.INFO {
		return fmt.Errorf("invalid log level %d", level)
	}
	l.level = level
	return nil
}

func (l *LogController) GetLogFunc() func(args ...interface{}) {
	if l.level == logging.DEBUG {
		return log.Debug
	}
	return log.Info
}
