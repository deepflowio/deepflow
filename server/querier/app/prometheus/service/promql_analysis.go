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

package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/querier/common"
)

func (e *prometheusExecutor) promQLAnalysis(ctx context.Context, metric string, targetLabels []string, appLabels []string, startTime string, endTime string, orgID string) (*common.Result, error) {
	startMs, err := strconv.ParseInt(startTime, 10, 64)
	if err != nil {
		log.Error(err)
		startMs = time.Now().Add(-5 * time.Minute).Unix()
	}
	endMs, err := strconv.ParseInt(endTime, 10, 64)
	if err != nil {
		log.Error(err)
		endMs = time.Now().Unix()
	}

	field := []string{
		"Sum(log_count) as `query_count`",
		"Avg(response_duration)/1000 as `avg_duration(ms)`",
		"Max(response_duration)/1000 as `max_duration(ms)`",
		"`attribute.promql.query.metric.name` as `metric_name`",
		"`attribute.promql.query.range` as `query_range`",
	}
	group := []string{"`metric_name`", "`query_range`"}

	filters := []string{
		fmt.Sprintf("time >= %d and time <= %d", startMs, endMs),
		"endpoint like 'Prometheus*Query'",
		"tap_port_type = 8",
	}
	if metric != "" {
		filters = append(filters, fmt.Sprintf("`metric_name` = '%s'", metric))
	}

	if len(targetLabels) > 0 {
		targetFilter := make([]string, 0, len(targetLabels))
		for _, v := range targetLabels {
			if v == "" {
				continue
			}
			if v != "*" {
				targetFilter = append(targetFilter, fmt.Sprintf("`target_labels` like '*%s*'", v))
			}
		}
		if len(targetFilter) > 0 {
			filters = append(filters, fmt.Sprintf("(%s)", strings.Join(targetFilter, " OR ")))
		}
		field = append(field, "`attribute.promql.query.metric.targetLabel` As `target_labels`")
		group = append(group, "`target_labels`")
	}

	if len(appLabels) > 0 {
		appFilter := make([]string, 0, len(appLabels))
		for _, v := range appLabels {
			if v == "" {
				continue
			}
			if v != "*" {
				appFilter = append(appFilter, fmt.Sprintf("`app_labels` like '*%s*'", v))
			}
		}
		if len(appFilter) > 0 {
			filters = append(filters, fmt.Sprintf("(%s)", strings.Join(appFilter, " OR ")))
		}
		field = append(field, "`attribute.promql.query.metric.appLabel` As `app_labels`")
		group = append(group, "`app_labels`")
	}

	sql := fmt.Sprintf("select %s from %s where %s group by %s order by `query_count` desc limit %d",
		strings.Join(field, ","),
		"l7_flow_log",
		strings.Join(filters, " AND "),
		strings.Join(group, ","),
		10000,
	)
	result, _, _, err := queryDataExecute(ctx, sql, "flow_log", "", orgID, false)
	return result, err
}
