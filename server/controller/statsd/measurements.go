package statsd

import (
	"reflect"

	k8sgathermodel "github.com/metaflowys/metaflow/server/controller/cloud/kubernetes_gather/model"
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
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
	PrivateTagValueToCount map[string][]int
}

type CloudStatsd struct {
	APICount map[string][]int
	APICost  map[string][]int
	ResCount map[string][]int
	TaskCost map[string][]int
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

	// init metric type Timing
	taskCost := StatsdElement{
		MetricType:             MetricTiming,
		MetricName:             common.CLOUD_METRIC_NAME_TASK_COST,
		UseGlobalTag:           false,
		PrivateTagKey:          "domain",
		PrivateTagValueToCount: cloud.TaskCost,
	}
	return []StatsdElement{apiCount, apiCost, resCount, taskCost}
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
