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

package statsd

import (
	"reflect"
	"time"

	k8sgathermodel "github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

const (
	MetricInc    = "Inc"
	MetricTiming = "Timing"
)

type Statsdtable interface {
	GetStatter() StatsdStatter
}

type StatsdStatter struct {
	Element    []StatsdElement
	GlobalTags map[string]string
}
type StatsdElement struct {
	// metric type (specified by a constant)
	MetricType string
	// influxdb measurement name (if there is a configuration prefix, the prefix must be added)
	MetricName string
	// the default value is 1.0, usually no modification is required
	Rate float32
	// use global tags
	UseGlobalTag bool
	// private tag key
	PrivateTagKey string
	// private tag value to count
	// when the type is Timing，unit is: ms
	// since this is a map, concurrent writing is not supported and locks can be used if required.
	// future: it might be useful sync.Map
	PrivateTagValueToCount map[string][]int
}

type CloudStatsd struct {
	APICount map[string][]int
	APICost  map[string][]int
	ResCount map[string][]int
}

func NewCloudStatsd() CloudStatsd {
	return CloudStatsd{
		APICount: make(map[string][]int),
		APICost:  make(map[string][]int),
		ResCount: make(map[string][]int),
	}
}

func (c *CloudStatsd) RefreshAPICount(key string, count int) {
	if _, ok := c.APICount[key]; !ok {
		c.APICount[key] = []int{count}
	} else {
		c.APICount[key] = append(c.APICount[key], count)
	}
}

func (c *CloudStatsd) RefreshAPICost(key string, start time.Time) {
	cost := time.Now().Sub(start).Milliseconds()
	if _, ok := c.APICost[key]; !ok {
		c.APICost[key] = []int{int(cost)}
	} else {
		c.APICost[key] = append(c.APICost[key], int(cost))
	}
}

func (c *CloudStatsd) RefreshResCount(resource model.Resource) {
	c.ResCount = GetResCount(resource)
}

func GetCloudStatsd(cloud CloudStatsd) []StatsdElement {
	// init metric type Inc
	apiCount := StatsdElement{
		MetricType:             MetricInc,
		MetricName:             common.CLOUD_METRIC_NAME_API_COUNT,
		UseGlobalTag:           true,
		PrivateTagKey:          "type",
		PrivateTagValueToCount: cloud.APICount,
	}

	// init metric type Timing
	apiCost := StatsdElement{
		MetricType:             MetricTiming,
		MetricName:             common.CLOUD_METRIC_NAME_API_COST,
		UseGlobalTag:           true,
		PrivateTagKey:          "type",
		PrivateTagValueToCount: cloud.APICost,
	}

	// init metric type Inc
	resCount := StatsdElement{
		MetricType:             MetricInc,
		MetricName:             common.CLOUD_METRIC_NAME_INFO_COUNT,
		UseGlobalTag:           true,
		PrivateTagKey:          "type",
		PrivateTagValueToCount: cloud.ResCount,
	}

	return []StatsdElement{apiCount, apiCost, resCount}
}

type CloudTaskStatsd struct {
	TaskCost map[string][]int
}

func GetCloudTaskStatsd(cloud CloudTaskStatsd) []StatsdElement {
	// init metric type Timing
	taskCost := StatsdElement{
		MetricType:             MetricTiming,
		MetricName:             common.CLOUD_METRIC_NAME_TASK_COST,
		UseGlobalTag:           false,
		PrivateTagKey:          "domain",
		PrivateTagValueToCount: cloud.TaskCost,
	}

	return []StatsdElement{taskCost}
}

func GetResCount[T model.Resource | k8sgathermodel.KubernetesGatherResource](res T) map[string][]int {
	resCount := map[string][]int{}
	resAttr := reflect.TypeOf(res)
	resValue := reflect.ValueOf(res)
	for i := 0; i < resAttr.NumField(); i++ {
		var rCount int
		rKey := resAttr.Field(i).Name
		switch rKey {
		case "Verified", "ErrorState", "ErrorMessage":
			continue
		case "AZ", "VPC", "Region", "PodCluster", "PodNodeNetwork", "PodServiceNetwork", "PodNetwork":
			rCount = 1
		default:
			rCount = resValue.Field(i).Len()
		}
		if rCount == 0 {
			continue
		}
		resCount[rKey] = []int{rCount}
	}
	return resCount
}

type GenesisStatsd struct {
	K8SInfoDelay map[string][]int
}

func GetGenesisStatsd(genesis GenesisStatsd) []StatsdElement {
	k8sInfoDelay := StatsdElement{
		MetricType:             MetricTiming,
		MetricName:             common.GENESIS_METRIC_NAME_K8SINFO_DELAY,
		UseGlobalTag:           false,
		PrivateTagKey:          "cluster_id",
		PrivateTagValueToCount: genesis.K8SInfoDelay,
	}
	return []StatsdElement{k8sInfoDelay}
}
