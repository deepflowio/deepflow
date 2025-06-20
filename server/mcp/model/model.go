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

// Region 表示区域信息
type Region struct {
	Name string `json:"NAME"`
	ID   string `json:"ID"`
}

// ProfileData 表示profile分析数据
type ProfileData struct {
	FunctionTypes  []string  `json:"function_types"`
	FunctionNames  []string  `json:"functions"`
	FunctionValues DataFrame `json:"function_values"`
	NodeValues     DataFrame `json:"node_values"`
}

// DataFrame 简单的数据框架实现
type DataFrame struct {
	Columns []string        `json:"columns"`
	Values  [][]interface{} `json:"values"`
}

// ProfileNode 表示profile调用树中的节点
type ProfileNode struct {
	ID           int            `json:"id"`
	ParentID     int            `json:"parent_id"`
	FunctionName string         `json:"function_name"`
	FunctionType string         `json:"function_type"`
	SelfValue    float64        `json:"self_value"`
	TotalValue   float64        `json:"total_value"`
	Children     []*ProfileNode `json:"children,omitempty"`
}

// FunctionSummary 表示函数汇总信息
type FunctionSummary struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	SelfTime  float64 `json:"self_time"`
	TotalTime float64 `json:"total_time"`
}

// FunctionCallRelation 表示函数间的调用关系
type FunctionCallRelation struct {
	Caller string
	Callee string
}
