/**
 * Copyright (c) 2023 Yunshan Networks
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

package tool

import (
	"fmt"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("recorder.cache.tool")

func dbQueryResourceFailed(resource string, err error) string {
	return fmt.Sprintf("db query %s failed: %v", resource, err)
}

func dbResourceByLcuuidNotFound(resource, lcuuid string) string {
	return fmt.Sprintf("db %s (lcuuid: %s) not found", resource, lcuuid)
}

func dbResourceByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("db %s (id: %d) not found", resource, id)
}

func cacheLcuuidByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("cache %s lcuuid (id: %d) not found", resource, id)
}

func cacheIDByLcuuidNotFound(resource string, lcuuid string) string {
	return fmt.Sprintf("cache %s id (lcuuid: %s) not found", resource, lcuuid)
}

func addToToolMap(resource, lcuuid string) string {
	return fmt.Sprintf("cache tool map add %s (lcuuid: %s) success", resource, lcuuid)
}

func updateToolMap(resource, lcuuid string) string {
	return fmt.Sprintf("cache tool map update %s (lcuuid: %s) success", resource, lcuuid)
}

func deleteFromToolMap(resource, lcuuid string) string {
	return fmt.Sprintf("cache tool map delete %s (lcuuid: %s) success", resource, lcuuid)
}

func refreshResource(resource string) string {
	return fmt.Sprintf("refresh %s", resource)
}

func cacheNameByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("cache %s name (id: %d) not found", resource, id)
}

func cacheIPByLcuuidNotFound(resource, lcuuid string) string {
	return fmt.Sprintf("cache %s ip (lcuuid: %s) not found", resource, lcuuid)
}

func cacheRegionLcuuidByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("cache %s region (id: %d) not found", resource, id)
}

func cacheAZLcuuidByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("cache %s az (id: %d) not found", resource, id)
}

func cacheVPCIDByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("cache %s vpc id (id: %d) not found", resource, id)
}

func cacheLaunchServerByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("cache %s launch server (id: %d) not found", resource, id)
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
