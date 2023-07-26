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
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
)

func (e *prometheusExecutor) wrapResponse(res *model.PromQueryResponse) *model.PromQueryWrapper {
	result := &model.PromQueryWrapper{
		OptStatus:   res.Status,
		Description: res.Error,
		Type:        "promql",
	}

	if res.Data != nil {
		data := res.Data.(*model.PromQueryData)
		switch data.ResultType {
		case parser.ValueTypeVector:
			vector := data.Result.(promql.Vector)
			result.Data = make([](map[string]interface{}), 0, len(vector))
			for _, v := range vector {
				vectorData := make(map[string]interface{}, len(v.Metric)+3)
				vectorData["query_id"] = "R1"
				metricLabels := make(map[string]string, len(v.Metric))
				for _, label := range v.Metric {
					metricLabels[label.Name] = label.Value
				}
				vectorData["metrics"] = metricLabels
				history := []model.WrapHistorySeries{
					{
						Toi:   v.T,
						Value: v.V,
					},
				}
				vectorData["HISTORY"] = history
				result.Data = append(result.Data, vectorData)
			}
		case parser.ValueTypeMatrix:
			matrix := data.Result.(promql.Matrix)
			result.Data = make([](map[string]interface{}), 0, len(matrix))
			for _, v := range matrix {
				matricData := make(map[string]interface{}, len(v.Metric)+3)
				matricData["query_id"] = "R1"
				metricLabels := make(map[string]string, len(v.Metric))
				for _, label := range v.Metric {
					metricLabels[label.Name] = label.Value
				}
				matricData["metrics"] = metricLabels
				history := make([]model.WrapHistorySeries, 0, len(v.Points))
				for _, p := range v.Points {
					history = append(history, model.WrapHistorySeries{
						Toi:   p.T,
						Value: p.V,
					})
				}
				matricData["HISTORY"] = history
				result.Data = append(result.Data, matricData)
			}
		case parser.ValueTypeScalar:
			scalar := data.Result.(promql.Scalar)
			result.Data = make([](map[string]interface{}), 0, 1)
			scalarData := map[string]interface{}{
				"query_id": "R1",
				"HISTORY": []model.WrapHistorySeries{
					{
						Toi:   scalar.T,
						Value: scalar.V,
					},
				}}
			result.Data = append(result.Data, scalarData)
		default:
			return result
		}
	}
	return result
}
