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

package handle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/mark3labs/mcp-go/mcp"
	logging "github.com/op/go-logging"

	ccommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/mcp/common"
	"github.com/deepflowio/deepflow/server/mcp/config"
	"github.com/deepflowio/deepflow/server/mcp/model"
)

var log = logging.MustGetLogger("mcp.handle")

// fetchAndanalyzeProfileData 获取并分析profile数据的工具函数
func FetchAndAnalyzeProfileData(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	commitID := request.GetString("commit_id", "")
	if commitID == "" {
		return nil, errors.New(translation("commit_id 参数不能为空"))
	}

	startTimeStr := request.GetString("start_time", "0")
	endTimeStr := request.GetString("end_time", "0")

	startTime, err := parseTimeToUnix(startTimeStr)
	if err != nil {
		return nil, fmt.Errorf(translation("解析开始时间失败")+": %w", err)
	}

	endTime, err := parseTimeToUnix(endTimeStr)
	if err != nil {
		return nil, fmt.Errorf(translation("解析结束时间失败")+": %w", err)
	}

	// 获取profile数据
	profileData, err := getProfileData(commitID, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf(translation("获取profile数据失败")+": %w", err)
	}

	// 计算函数汇总
	summaries := calculateFunctionSummaries(profileData)

	// 不再需要构建调用树，直接使用函数级别的图

	// 生成报告
	var report strings.Builder
	report.WriteString(fmt.Sprintf("# %s\n\n", translation("Profile 分析报告")))
	report.WriteString(fmt.Sprintf("**Commit ID**: %s\n", commitID))

	if startTime != 0 && endTime != 0 {
		report.WriteString(fmt.Sprintf("**%s**: %s - %s\n", translation("时间范围"),
			time.Unix(startTime, 0).Format("2006-01-02 15:04:05"),
			time.Unix(endTime, 0).Format("2006-01-02 15:04:05")))
	} else {
		report.WriteString(fmt.Sprintf("**%s**: %s\n", translation("时间范围"), translation("最近5分钟")))
	}
	report.WriteString("\n")

	// Top 10 函数
	report.WriteString(fmt.Sprintf("## %s\n\n", translation("Top 10 函数（按自身耗时排序）")))
	report.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", translation("函数名"), translation("类型"), translation("自身耗时"), translation("总耗时")))
	report.WriteString("|--------|------|----------|--------|\n")

	topCount := common.TOP_FUNCTIONS_COUNT
	if len(summaries) < topCount {
		topCount = len(summaries)
	}

	for i := 0; i < topCount; i++ {
		summary := summaries[i]
		report.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
			escapeFunctionName(summary.Name),
			summary.Type,
			formatDuration(summary.SelfTime),
			formatDuration(summary.TotalTime)))
	}

	// 调用关系图
	report.WriteString(fmt.Sprintf("\n## %s\n\n", translation("调用关系图")))
	report.WriteString(generateFunctionMermaidDiagram(profileData))
	report.WriteString("\n\n")
	report.WriteString(translation(common.KNOWLEDGE_TEXT))

	log.Info(report.String())

	return mcp.NewToolResultText(report.String()), nil
}

func translation(input string) string {
	if config.MConfig == nil {
		return input
	}
	switch config.MConfig.QuerierLanguage {
	case "ch":
		return input
	case "en":
		return common.TEXT_CN_TO_EN[input]
	default:
		return input
	}
}

// getDefaultTimeRange 获取默认时间范围（最近5分钟）
func getDefaultTimeRange() (int64, int64) {
	endTime := time.Now().Unix()
	startTime := endTime - common.DEFAULT_TIME_RANGE_MINUTES*60
	return startTime, endTime
}

// getProfileData 获取profile数据
func getProfileData(commitID string, startTime, endTime int64) (*model.ProfileData, error) {
	if err := validateCommitID(commitID); err != nil {
		return nil, fmt.Errorf(translation("commit ID 验证失败")+": %w", err)
	}

	// 如果时间参数为0，使用默认时间范围
	if startTime == 0 || endTime == 0 {
		startTime, endTime = getDefaultTimeRange()
	}

	apiTemplate := map[string]interface{}{
		"profile_language_type":  "eBPF",
		"profile_event_type":     "on-cpu",
		"tag_filter":             fmt.Sprintf("`k8s.label.git_commit_id`='%s'", commitID),
		"max_kernel_stack_depth": 0,
		"time_start":             startTime,
		"time_end":               endTime,
	}
	log.Debugf("sql %#v", apiTemplate)

	profileURL := fmt.Sprintf(common.PROFILE_API_URL_FORMAT, config.MConfig.QuerierPort)
	respJson, err := ccommon.CURLPerform("POST", profileURL, apiTemplate)
	if err != nil {
		log.Errorf("获取profile数据失败: %v", err)
		return nil, err
	}

	dataJson := respJson.Get("result")
	profileData := &model.ProfileData{}

	// 解析function_types
	if functionTypes := dataJson.Get("function_types").MustArray(); functionTypes != nil {
		profileData.FunctionTypes = make([]string, len(functionTypes))
		for i, ft := range functionTypes {
			profileData.FunctionTypes[i] = fmt.Sprintf("%v", ft)
		}
	}

	// 解析function_names
	if functionNames := dataJson.Get("functions").MustArray(); functionNames != nil {
		profileData.FunctionNames = make([]string, len(functionNames))
		for i, fn := range functionNames {
			profileData.FunctionNames[i] = fmt.Sprintf("%v", fn)
		}
	}

	// 解析function_values
	if functionValues := dataJson.Get("function_values"); functionValues != nil {
		profileData.FunctionValues = parseDataFrame(functionValues)
	}

	// 解析node_values
	if nodeValues := dataJson.Get("node_values"); nodeValues != nil {
		profileData.NodeValues = parseDataFrame(nodeValues)
	}

	return profileData, nil
}

// parseDataFrame 解析DataFrame结构
func parseDataFrame(dataJson *simplejson.Json) model.DataFrame {
	df := model.DataFrame{}

	if columns := dataJson.Get("columns").MustArray(); columns != nil {
		df.Columns = make([]string, len(columns))
		for i, col := range columns {
			df.Columns[i] = fmt.Sprintf("%v", col)
		}
	}

	if values := dataJson.Get("values").MustArray(); values != nil {
		df.Values = make([][]interface{}, len(values))
		for i, row := range values {
			if rowArray, ok := row.([]interface{}); ok {
				df.Values[i] = rowArray
			}
		}
	}

	return df
}

// formatDuration 格式化持续时间（微秒转换为人可读格式）
func formatDuration(microseconds float64) string {
	if microseconds < 1000 {
		return fmt.Sprintf("%.1fμs", microseconds)
	} else if microseconds < 1000000 {
		return fmt.Sprintf("%.1fms", microseconds/1000)
	} else {
		return fmt.Sprintf("%.2fs", microseconds/1000000)
	}
}

// escapeFunctionName 转义函数名称中的特殊字符，避免影响 Markdown 和 Mermaid 输出
func escapeFunctionName(name string) string {
	// 替换可能影响 Markdown 表格的字符
	name = strings.ReplaceAll(name, "|", "\\|")

	// 替换可能影响 Mermaid 图的字符
	name = strings.ReplaceAll(name, "\"", "\\\"")
	name = strings.ReplaceAll(name, "[", "\\[")
	name = strings.ReplaceAll(name, "]", "\\]")
	name = strings.ReplaceAll(name, "(", "\\(")
	name = strings.ReplaceAll(name, ")", "\\)")
	name = strings.ReplaceAll(name, "{", "\\{")
	name = strings.ReplaceAll(name, "}", "\\}")
	name = strings.ReplaceAll(name, "<", "&lt;")
	name = strings.ReplaceAll(name, ">", "&gt;")
	name = strings.ReplaceAll(name, "&", "&amp;")

	// 处理可能的换行符
	name = strings.ReplaceAll(name, "\n", " ")
	name = strings.ReplaceAll(name, "\r", " ")
	name = strings.ReplaceAll(name, "\t", " ")

	return name
}

// convertToFloat64 安全地将interface{}转换为float64
func convertToFloat64(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case json.Number:
		return val.Float64()
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("无法转换类型 %T 为 float64", v)
	}
}

// convertToInt 安全地将interface{}转换为int
func convertToInt(v interface{}) (int, error) {
	f64, err := convertToFloat64(v)
	if err != nil {
		return 0, err
	}
	return int(f64), nil
}

// parseTimeToUnix 解析时间字符串或时间戳为Unix秒时间戳
func parseTimeToUnix(timeStr string) (int64, error) {
	// 如果是空字符串或"0"，返回0
	if timeStr == "" || timeStr == "0" {
		return 0, nil
	}

	// 首先尝试解析为数字（时间戳）
	if timestamp, err := strconv.ParseInt(timeStr, 10, 64); err == nil {
		// 如果数字很大，可能是毫秒时间戳，转换为秒
		if timestamp > 9999999999 { // 大于10位数，可能是毫秒时间戳
			return timestamp / 1000, nil
		}
		return timestamp, nil
	}

	// 如果不是数字，尝试解析为时间字符串
	// 支持的时间格式
	timeFormats := []string{
		"2006-01-02T15:04:05Z07:00",     // RFC3339
		"2006-01-02T15:04:05Z",          // RFC3339 UTC
		"2006-01-02T15:04:05",           // ISO 8601 without timezone
		"2006-01-02 15:04:05",           // 常见格式
		"2006-01-02T15:04:05.999Z07:00", // RFC3339 with milliseconds
		"2006-01-02T15:04:05.999Z",      // RFC3339 UTC with milliseconds
		"2006-01-02 15:04:05.999",       // 常见格式 with milliseconds
		"2006-01-02",                    // 日期格式
		"15:04:05",                      // 时间格式（今天）
		"01/02/2006 15:04:05",           // 美式格式
		"01/02/2006",                    // 美式日期格式
		"2006/01/02 15:04:05",           // 日式格式
		"2006/01/02",                    // 日式日期格式
	}

	for _, format := range timeFormats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t.Unix(), nil
		}
	}

	// 如果所有格式都失败，尝试使用相对时间解析
	// 支持相对时间表达式，如 "1h", "30m", "1d" 等
	if duration, err := time.ParseDuration(timeStr); err == nil {
		return time.Now().Add(duration).Unix(), nil
	}

	return 0, fmt.Errorf("无法解析时间格式: %s", timeStr)
}

// calculateFunctionSummaries 计算函数汇总信息
func calculateFunctionSummaries(profileData *model.ProfileData) []model.FunctionSummary {
	functionSummaries := make(map[string]*model.FunctionSummary)

	// 从function_values中获取总体统计
	for i, row := range profileData.FunctionValues.Values {
		if len(row) < 2 || i >= len(profileData.FunctionNames) {
			continue
		}

		functionName := profileData.FunctionNames[i]

		selfTime, err := convertToFloat64(row[0])
		if err != nil {
			log.Errorf(translation("转换selfTime失败")+": %v", err)
			continue
		}

		totalTime, err := convertToFloat64(row[1])
		if err != nil {
			log.Errorf(translation("转换totalTime失败")+": %v", err)
			continue
		}

		var functionType string
		if i < len(profileData.FunctionTypes) {
			functionType = profileData.FunctionTypes[i]
		}

		if summary, exists := functionSummaries[functionName]; exists {
			summary.SelfTime += selfTime
			summary.TotalTime += totalTime
		} else {
			functionSummaries[functionName] = &model.FunctionSummary{
				Name:      functionName,
				Type:      functionType,
				SelfTime:  selfTime,
				TotalTime: totalTime,
			}
		}
	}

	// 转换为切片并排序
	summaries := make([]model.FunctionSummary, 0, len(functionSummaries))
	for _, summary := range functionSummaries {
		summaries = append(summaries, *summary)
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].SelfTime > summaries[j].SelfTime
	})

	return summaries
}

// validateCommitID 验证commit ID的有效性
func validateCommitID(commitID string) error {
	if len(commitID) > common.MAX_COMMIT_ID_LENGTH {
		return fmt.Errorf(translation("commit ID 长度超过限制")+" (%d)", common.MAX_COMMIT_ID_LENGTH)
	}

	// 检查是否包含异常字符
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, commitID)
	if err != nil {
		return fmt.Errorf(translation("正则表达式验证失败")+": %w", err)
	}
	if !matched {
		return errors.New(translation("commit ID 包含异常字符"))
	}

	return nil
}

// generateFunctionMermaidDiagram 生成函数级别的Mermaid调用关系图
func generateFunctionMermaidDiagram(profileData *model.ProfileData) string {
	var builder strings.Builder
	builder.WriteString("```mermaid\n")
	builder.WriteString("graph TD\n")

	// 收集所有函数间的调用关系
	callRelations := make(map[model.FunctionCallRelation]bool)
	allFunctions := make(map[string]bool)

	// 遍历所有节点，提取函数间调用关系
	for _, row := range profileData.NodeValues.Values {
		if len(row) < 4 {
			continue
		}

		nodeID, err := convertToInt(row[0])
		if err != nil {
			continue
		}

		parentID, err := convertToInt(row[1])
		if err != nil {
			continue
		}

		// 获取当前节点的函数名
		var currentFunction string
		if nodeID < len(profileData.FunctionNames) {
			currentFunction = profileData.FunctionNames[nodeID]
			allFunctions[currentFunction] = true
		}

		// 如果有父节点，建立调用关系
		if parentID != -1 && parentID < len(profileData.FunctionNames) {
			parentFunction := profileData.FunctionNames[parentID]
			allFunctions[parentFunction] = true

			// 记录调用关系：父函数调用子函数
			if parentFunction != currentFunction { // 避免自调用
				callRelations[model.FunctionCallRelation{
					Caller: parentFunction,
					Callee: currentFunction,
				}] = true
			}
		}
	}

	// 收集所有函数的时间信息，用于排序
	type FunctionInfo struct {
		Name         string
		Index        int
		SelfTime     float64
		TotalTime    float64
		FunctionType string
	}

	var functionInfos []FunctionInfo
	for i, functionName := range profileData.FunctionNames {
		if !allFunctions[functionName] {
			continue
		}

		// 获取函数的时间信息
		var selfTime, totalTime float64
		if i < len(profileData.FunctionValues.Values) {
			row := profileData.FunctionValues.Values[i]
			if len(row) >= 2 {
				selfTime, _ = convertToFloat64(row[0])
				totalTime, _ = convertToFloat64(row[1])
			}
		}

		// 获取函数类型
		var functionType string
		if i < len(profileData.FunctionTypes) {
			functionType = profileData.FunctionTypes[i]
		}

		functionInfos = append(functionInfos, FunctionInfo{
			Name:         functionName,
			Index:        i,
			SelfTime:     selfTime,
			TotalTime:    totalTime,
			FunctionType: functionType,
		})
	}

	// 按total时间排序，选择Top N个函数
	sort.Slice(functionInfos, func(i, j int) bool {
		return functionInfos[i].TotalTime > functionInfos[j].TotalTime
	})

	// 限制显示的函数数量
	if len(functionInfos) > common.MAX_NODES_IN_TREE {
		functionInfos = functionInfos[:common.MAX_NODES_IN_TREE]
	}

	// 创建函数ID映射和显示的函数集合
	functionIDs := make(map[string]string)
	displayedFunctions := make(map[string]bool)

	// 生成函数节点
	for functionCount, funcInfo := range functionInfos {
		functionID := fmt.Sprintf("func%d", functionCount)
		functionIDs[funcInfo.Name] = functionID
		displayedFunctions[funcInfo.Name] = true

		label := fmt.Sprintf("[%s] %s(%s/%s)",
			funcInfo.FunctionType,
			escapeFunctionName(funcInfo.Name),
			formatDuration(funcInfo.SelfTime),
			formatDuration(funcInfo.TotalTime))

		builder.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", functionID, label))
	}

	// 生成调用关系
	builder.WriteString("\n")
	relationCount := 0
	for relation := range callRelations {
		callerID, callerExists := functionIDs[relation.Caller]
		calleeID, calleeExists := functionIDs[relation.Callee]

		if callerExists && calleeExists {
			builder.WriteString(fmt.Sprintf("    %s --> %s\n", callerID, calleeID))
			relationCount++
		}
	}

	// 添加统计信息
	builder.WriteString(fmt.Sprintf("\n    info[\"%s\"]\n", translation("显示了 %d 个函数，%d 条调用关系"), len(functionInfos), relationCount))
	builder.WriteString("    style info fill:#e1f5fe,stroke:#01579b\n")

	builder.WriteString("```\n")
	return builder.String()
}
