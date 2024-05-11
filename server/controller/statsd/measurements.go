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
	OrgID      int
	TeamID     int
	Element    []StatsdElement
	GlobalTags map[string]string
}
type StatsdElement struct {
	// metric type (specified by a constant)
	MetricType string
	// clickhouse metrics field (if there is a configuration prefix, the prefix must be added)
	VirtualTableName string
	// use global tags
	UseGlobalTag bool
	// private tag key
	PrivateTagKey string
	// metrics float name to values
	MetricsFloatNameToValues map[string][]float64
}

type CloudStatsd struct {
	APICount map[string][]float64
	ResCount map[string][]float64
	APICost  map[string][]float64
}

func NewCloudStatsd() CloudStatsd {
	return CloudStatsd{
		APICount: make(map[string][]float64),
		ResCount: make(map[string][]float64),
		APICost:  make(map[string][]float64),
	}
}

func (c *CloudStatsd) RefreshAPIMoniter(key string, count int, start time.Time) {
	var cost float64 = 0
	if !start.IsZero() {
		cost = time.Now().Sub(start).Seconds()
	}
	c.APICost[key] = append(c.APICost[key], cost)
	c.APICount[key] = append(c.APICount[key], float64(count))
}

func GetCloudStatsd(cloud CloudStatsd) []StatsdElement {
	// init metric type Inc
	apiCount := StatsdElement{
		MetricType:               MetricInc,
		VirtualTableName:         common.CLOUD_METRIC_NAME_API_COUNT,
		UseGlobalTag:             true,
		PrivateTagKey:            "type",
		MetricsFloatNameToValues: cloud.APICount,
	}

	// init metric type Timing
	apiCost := StatsdElement{
		MetricType:               MetricTiming,
		VirtualTableName:         common.CLOUD_METRIC_NAME_API_COST,
		UseGlobalTag:             true,
		PrivateTagKey:            "type",
		MetricsFloatNameToValues: cloud.APICost,
	}

	// init metric type Inc
	resCount := StatsdElement{
		MetricType:               MetricInc,
		VirtualTableName:         common.CLOUD_METRIC_NAME_INFO_COUNT,
		UseGlobalTag:             true,
		PrivateTagKey:            "type",
		MetricsFloatNameToValues: cloud.ResCount,
	}

	return []StatsdElement{apiCount, apiCost, resCount}
}

type CloudTaskStatsd struct {
	TaskCost map[string][]float64
}

func GetCloudTaskStatsd(cloud CloudTaskStatsd) []StatsdElement {
	// init metric type Timing
	taskCost := StatsdElement{
		MetricType:               MetricTiming,
		VirtualTableName:         common.CLOUD_METRIC_NAME_TASK_COST,
		UseGlobalTag:             false,
		PrivateTagKey:            "domain",
		MetricsFloatNameToValues: cloud.TaskCost,
	}

	return []StatsdElement{taskCost}
}

func GetResCount[T model.Resource | k8sgathermodel.KubernetesGatherResource](res T) map[string][]float64 {
	resCount := map[string][]float64{}
	resAttr := reflect.TypeOf(res)
	resValue := reflect.ValueOf(res)
	for i := 0; i < resAttr.NumField(); i++ {
		var rCount float64
		rKey := resAttr.Field(i).Name
		switch rKey {
		case "Verified", "ErrorState", "ErrorMessage", "SyncAt":
			continue
		case "AZ", "VPC", "Region", "PodCluster", "PodNodeNetwork", "PodServiceNetwork", "PodNetwork":
			rCount = 1
		default:
			rCount = float64(resValue.Field(i).Len())
		}
		if rCount == 0 {
			continue
		}
		resCount[rKey] = []float64{rCount}
	}
	return resCount
}

type GenesisStatsd struct {
	K8SInfoDelay map[string][]float64
}

func GetGenesisStatsd(genesis GenesisStatsd) []StatsdElement {
	k8sInfoDelay := StatsdElement{
		MetricType:               MetricTiming,
		VirtualTableName:         common.GENESIS_METRIC_NAME_K8SINFO_DELAY,
		UseGlobalTag:             false,
		PrivateTagKey:            "cluster_id",
		MetricsFloatNameToValues: genesis.K8SInfoDelay,
	}
	return []StatsdElement{k8sInfoDelay}
}
