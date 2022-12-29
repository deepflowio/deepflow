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

package event

import (
	"fmt"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("recorder.event")

func putEventIntoQueueFailed(resource string, err error) string {
	return fmt.Sprintf("put %s event into queue failed: %s", resource, err.Error())
}

func idByLcuuidNotFound(resource, lcuuid string) string {
	return fmt.Sprintf("%s (lcuuid: %s) id not found", resource, lcuuid)
}

func nameByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("%s (id: %d) name not found", resource, id)
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

func dbQueryFailed(err error) string {
	return fmt.Sprintf("db query failed: %v", err)
}

func dbSoftDeletedResourceByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("db soft deleted %s (id: %d) not found", resource, id)
}

func idByIPNotFound(resource, ip string) string {
	return fmt.Sprintf("%s (ip: %s) id not found", resource, ip)
}
