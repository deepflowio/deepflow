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

package view

const (
	NODE_FLAG_METRICS       int = iota // 仅在计算层
	NODE_FLAG_METRICS_INNER            // 仅在计算层内层
	NODE_FLAG_METRICS_OUTER            // 仅在计算层外层
	NODE_FLAG_METRICS_TOP              // 仅在最外层
)

const (
	METRICS_FLAG_INNER int = iota // METRICS专用FLAG，仅在计算层内层
	METRICS_FLAG_OUTER            // METRICS专用FLAG，仅在计算层外层
	METRICS_FLAG_TOP              // METRICS专用FLAG，在整体sql外再增加一层，仅包含该FLAG的字段
)

const (
	GROUP_FLAG_DEFAULT        int = iota // GROUP专用FLAG，计算层内外都携带group，with仅放计算层内层
	GROUP_FLAG_METRICS_OUTER             // GROUP专用FLAG，仅计算层外层携带该group
	GROUP_FLAG_METRICS_INNTER            // GROUP专用FLAG，仅计算层内层携带该group
)

const (
	MODEL_METRICS_LEVEL_FLAG_UNLAY   int = iota // 计算层不需要根据算子拆层
	MODEL_METRICS_LEVEL_FLAG_LAYERED            // 计算层需要根据算子拆层
)

// Div算子类型
const (
	FUNCTION_DIV_TYPE_DEFAULT          int = iota // 默认，不做任何处理
	FUNCTION_DIV_TYPE_FILL_MINIMUM                // 除数和被除数都+1e-15
	FUNCTION_DIV_TYPE_0DIVIDER_AS_NULL            // 除数为0时，结果为NULL
	FUNCTION_DIV_TYPE_0DIVIDER_AS_0               //除数为0时，结果为0
)
