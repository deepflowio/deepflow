/*
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
package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzer(t *testing.T) {
	analyzer := newQueryAnalyzer(5 * time.Minute)

	t.Run("test parser count_over_time(node_cpu_seconds_total[5m])", func(t *testing.T) {
		qrs := analyzer.parsePromQL("count_over_time(node_cpu_seconds_total[5m])", time.Now(), time.Now(), 1*time.Minute)
		assert.Greater(t, len(qrs), 0)
		qr0 := qrs[0]
		assert.Equal(t, qr0.GetFunc(), []string{"count_over_time"})
		assert.Equal(t, qr0.GetRange("count_over_time"), (5 * time.Minute).Milliseconds())
	})

	t.Run("test parser max by (namespace,pod,node,owner_name,owner_kind,qos,cluster)(kube_pod_info{})", func(t *testing.T) {
		qrs := analyzer.parsePromQL("max by (namespace,pod,node,owner_name,owner_kind,qos,cluster)(kube_pod_info{})", time.Now(), time.Now(), 1*time.Minute)
		assert.Greater(t, len(qrs), 0)
		qr0 := qrs[0]
		assert.Equal(t, qr0.GetFunc(), []string{"max"})
		assert.Equal(t, qr0.GetGrouping("max"), []string{"namespace", "pod", "node", "owner_name", "owner_kind", "qos", "cluster"})
	})

	t.Run("test parser sum(irate(apiserver_request_total[5m])) by (verb,cluster)", func(t *testing.T) {
		qrs := analyzer.parsePromQL("sum(irate(apiserver_request_total[5m])) by (verb,cluster)", time.Now(), time.Now(), 1*time.Minute)
		assert.Greater(t, len(qrs), 0)
		qr0 := qrs[0]
		assert.Equal(t, qr0.GetFunc(), []string{"irate", "sum"})
		assert.Equal(t, qr0.GetRange("irate"), (5 * time.Minute).Milliseconds())
		assert.Equal(t, qr0.GetGrouping("sum"), []string{"verb", "cluster"})
	})

	t.Run(`test parser (sum by(cluster) (rate(scheduler_e2e_scheduling_duration_seconds_sum{job="kube-scheduler"}[1h]))  / sum by(cluster) (rate(scheduler_e2e_scheduling_duration_seconds_count{job="kube-scheduler"}[1h])))`, func(t *testing.T) {
		qrs := analyzer.parsePromQL(`(sum by(cluster) (rate(scheduler_e2e_scheduling_duration_seconds_sum{job="kube-scheduler"}[1h]))  / sum by(cluster) (rate(scheduler_e2e_scheduling_duration_seconds_count{job="kube-scheduler"}[1h])))`, time.Now(), time.Now(), 1*time.Minute)
		assert.Greater(t, len(qrs), 0)
		qr0 := qrs[0]
		assert.Equal(t, qr0.GetFunc(), []string{"rate", "sum"})
		assert.Equal(t, qr0.GetRange("rate"), (1 * time.Hour).Milliseconds())
		assert.Equal(t, qr0.GetGrouping("sum"), []string{"cluster"})

		qr1 := qrs[1]
		assert.Equal(t, qr1.GetFunc(), []string{"rate", "sum"})
		assert.Equal(t, qr1.GetRange("rate"), (1 * time.Hour).Milliseconds())
		assert.Equal(t, qr1.GetGrouping("sum"), []string{"cluster"})
	})
}
