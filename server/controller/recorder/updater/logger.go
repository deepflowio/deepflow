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

package updater

import (
	"fmt"
	"reflect"

	"github.com/op/go-logging"
	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/server/controller/recorder/config"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

var log = logging.MustGetLogger("recorder.updater")

func resourceAForResourceBNotFound(resourceA, lcuuidA, resourceB, lcuuidB string) string {
	return fmt.Sprintf("%s (lcuuid: %s) for %s (lcuuid: %s) not found", resourceA, lcuuidA, resourceB, lcuuidB)
}

func ipIsInvalid(resource, lcuuid, ip string) string {
	return fmt.Sprintf("%s (lcuuid: %s) ip: %s is invalid", resource, lcuuid, ip)
}

func debugCloudItem[CT constraint.CloudModel](resourceType string, cloudItem CT) string {
	if config.Get().LogDebug.DetailEnabled {
		return fmt.Sprintf("debug %s: %#v", resourceType, cloudItem)
	}
	return fmt.Sprintf("debug %s: %s", resourceType, getCloudItemLcuuid(cloudItem))
}

func logDebugResourceTypeEnabled(resourceType string) bool {
	if config.Get().LogDebug.Enabled {
		if slices.Contains(config.Get().LogDebug.ResourceTypes, resourceType) || slices.Contains(config.Get().LogDebug.ResourceTypes, "all") {
			return true
		}
	}
	return false
}

func logDebugEnabled() bool {
	return config.Get().LogDebug.Enabled
}

func getCloudItemLcuuid[CT constraint.CloudModel](cloudItem CT) string {
	value := reflect.ValueOf(cloudItem).FieldByName("Lcuuid")
	if value.IsValid() {
		return value.String()
	}
	return ""
}
