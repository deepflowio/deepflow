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

package common

var TEXT_CN_TO_EN = map[string]string{
	"Profile 分析报告": "Profile Analysis Report",
	"时间范围":         "Time Range",
	"最近5分钟":        "Last 5 minutes",
	"Top 10 函数（按自身耗时排序）": "Top 10 Functions (Sorted by Self Time)",
	"函数名":   "Function Name",
	"类型":    "Type",
	"自身耗时":  "Self Time",
	"总耗时":   "Total Time",
	"调用关系图": "Call Relationship Diagram",
	"显示了 %d 个函数，%d 条调用关系": "Showing %d functions, %d call relationships",
	"commit_id 参数不能为空":    "commit_id parameter cannot be empty",
	"解析开始时间失败":            "Failed to parse start time",
	"解析结束时间失败":            "Failed to parse end time",
	"获取profile数据失败":       "Failed to get profile data",
	"commit ID 验证失败":      "Commit ID validation failed",
	"commit ID 长度超过限制":    "Commit ID length exceeds limit",
	"commit ID 包含异常字符":    "Commit ID contains invalid characters",
	"无法转换类型":              "Cannot convert type",
	"无法解析时间格式":            "Cannot parse time format",
	"转换selfTime失败":        "Failed to convert selfTime",
	"转换totalTime失败":       "Failed to convert totalTime",
	"正则表达式验证失败":           "Regular expression validation failed",
	KNOWLEDGE_TEXT:        "\n * Background Knowledge:\n - Node names starting with [t] represent threads, [p] represents processes, [k] represents Linux kernel functions, [l] represents functions in dynamic link libraries\n Self time is the time consumed by the node itself, total time is the time consumed by the node itself + child nodes\n - Call relationship diagram shows the calling relationships between nodes, from parent nodes to child nodes\n\n * Note:\n When interpreting results:\n 1. Top 10 functions are presented in table format\n 2. Display the complete call relationship diagram above using Diagram\n 3. Analyze possible bottlenecks and issues, and provide a brief summary\n ",
}

const (
	MAX_COMMIT_ID_LENGTH       = 64
	DEFAULT_TIME_RANGE_MINUTES = 5
	MAX_NODES_IN_TREE          = 100
	TOP_FUNCTIONS_COUNT        = 10

	DEFAULT_REGION_NAME    = "系统默认"
	PROFILE_API_URL_FORMAT = "http://127.0.0.1:%d/v1/profile/ProfileTracing"

	KNOWLEDGE_TEXT = `
* 背景知识：
- 节点名以 [t] 开头表示一个线程，以 [p] 开头表示一个进程, 以 [k] 开头表示一个 Linux 内核函数, 以 [l] 开头表示一个动态链接库中的函数
自身消耗时间为节点自身消耗的时间，总消耗时间为节点自身消耗的时间 + 子节点消耗的时间
- 调用关系图表示节点之间的调用关系, 从父节点指向子节点

* 注意：
解读结果时
1. Top10 函数用表格形式呈现
2. 将上面完整的调用关系图用 Diagram 显示出来
3. 分析可能的瓶颈和问题，并做个简单总结
`
)
