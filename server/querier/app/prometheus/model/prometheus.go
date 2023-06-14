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

package model

import (
	"context"

	"github.com/prometheus/prometheus/promql/parser"
)

type PromQueryParams struct {
	MetricsWithPrefix string
	Promql            string
	StartTime         string
	EndTime           string
	Step              string
	Matchers          []string
	Context           context.Context
}

type PromQueryData struct {
	ResultType parser.ValueType `json:"resultType"`
	Result     parser.Value     `json:"result"`
}

type PromQueryResponse struct {
	Status    string      `json:"status"`
	Data      interface{} `json:"data,omitempty"`
	ErrorType errorType   `json:"errorType,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type PromMetaParams struct {
	StartTime string
	EndTime   string
	LabelName string
	Context   context.Context
}

type errorType string
