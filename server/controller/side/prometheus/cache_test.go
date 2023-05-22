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

package prometheus

import (
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/message/controller"
)

func TestGetDebugCache(t *testing.T) {
	type args struct {
		t controller.PrometheusCacheType
	}
	tests := []struct {
		name       string
		args       args
		beforeCall func()
		want       []byte
	}{
		{
			name: "get metric name",
			args: args{t: controller.PrometheusCacheType_METRIC_NAME},
			beforeCall: func() {
				c := GetSingleton().Cache
				c.metricName.setNameID("metric_name_1", 1)
				c.metricName.setNameID("metric_name_2", 2)
			},
			want: []byte(`{
	"metric_name": {
		"metric_name_to_id": {
			"metric_name_1": 1,
			"metric_name_2": 2
		}
	}
}`),
		},
		{
			name: "get all cache",
			args: args{t: controller.PrometheusCacheType_ALL},
			beforeCall: func() {
				c := GetSingleton().Cache
				c.labelName.setNameID("label_name_3", 3)
				c.labelValue.setValueID("label_value_4", 4)
				c.metricAndAPPLabelLayout.setIndex(appLabelIndexKey{MetricName: "cpu_total", LabelName: "job"}, 5)
				c.label.setNameValue("job", "k8s-pod")
				c.metricTarget.setTargetID("metric_target", 6)
			},
			want: []byte(`{
	"label": {
		"name_to_value": {
			"job": "k8s-pod"
		}
	},
	"label_name": {
		"label_name_to_id": {
			"label_name_3": 3
		}
	},
	"label_value": {
		"label_value_to_id": {
			"label_value_4": 4
		}
	},
	"metric_and_app_label_layout": {
		"metric_label_name_key_to_index": {
			"cpu_total-job": 5
		}
	},
	"metric_name": {
		"metric_name_to_id": {
			"metric_name_1": 1,
			"metric_name_2": 2
		}
	},
	"metric_target": {
		"metric_name_to_target_id": {
			"metric_target": 6
		}
	}
}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.beforeCall()
			got := GetDebugCache(tt.args.t)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetDebugCache() = %v, want %v", got, tt.want)
			}
		})
	}
}
