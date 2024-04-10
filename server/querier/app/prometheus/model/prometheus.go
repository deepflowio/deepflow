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

package model

import (
	"context"
	"time"

	"github.com/prometheus/prometheus/promql/parser"
)

type PromQueryParams struct {
	Debug      bool
	Offloading bool
	Slimit     int
	Promql     string
	StartTime  string
	EndTime    string
	Step       string
	OrgID      string
	Matchers   []string
	Context    context.Context
}

type PromQueryData struct {
	ResultType parser.ValueType `json:"resultType"`
	Result     parser.Value     `json:"result"`
}

type PromQueryResponse struct {
	Status    string           `json:"status"`
	Data      interface{}      `json:"data,omitempty"`
	ErrorType errorType        `json:"errorType,omitempty"`
	Error     string           `json:"error,omitempty"`
	Stats     []PromQueryStats `json:"stats,omitempty"`
}

type PromMetaParams struct {
	StartTime string
	EndTime   string
	LabelName string
	OrgID     string
	Context   context.Context
}

type PromQueryStats struct {
	Duration   float64 `json:"duration,omitempty"`
	SQL        string  `json:"sql,omitempty"`
	QuerierSQL string  `json:"querier_sql,omitempty"`
}

type errorType string

type PromQueryWrapper struct {
	OptStatus   string                     `json:"OPT_STATUS"`
	Type        string                     `json:"TYPE"` // promql
	Description string                     `json:"DESCRIPTION"`
	Schemas     struct{}                   `json:"SCHEMAS"`
	Data        [](map[string]interface{}) `json:"DATA"`
}

type WrapHistorySeries struct {
	Toi   int64   `json:"toi"`
	Value float64 `json:"value"`
}

type DeepFlowPromRequest struct {
	Slimit   int
	Start    int64
	End      int64
	Step     time.Duration
	Query    string
	OrgID    string
	Matchers []string
}
