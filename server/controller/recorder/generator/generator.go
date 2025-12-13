/*
 * Copyright (c) 2025 Yunshan Networks
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

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"

	"gopkg.in/yaml.v2"
)

type Field struct {
	Name              string `yaml:"name"`
	PublicName        string `yaml:"public_name"`
	Type              string `yaml:"type"`
	IsValidationField bool   `yaml:"is_validation_field"`
	Ref               string `yaml:"ref"`
	DbFieldName       string `yaml:"db_field_name"`
	HasSetter         bool   `yaml:"has_setter"`
	HasCustom         bool   `yaml:"has_custom"`
	IsCustom          bool   `yaml:"is_custom"`
	IsPlural          bool   `yaml:"is_plural"`
	Comment           string `yaml:"comment"`
	CamelName         string
	PublicCamelName   string
}

type KeyField struct {
	Name            string `yaml:"name"`
	PublicName      string `yaml:"public_name"`
	Type            string `yaml:"type"`
	CamelName       string
	PublicCamelName string
}

type CacheToolConfig struct {
	Enabled             bool       `yaml:"enabled"`
	Fields              []Field    `yaml:"fields"`
	KeyFields           []KeyField `yaml:"key_fields"`
	HasExtension        bool       `yaml:"has_extension"`
	CollectionExtension bool       `yaml:"collection_extension"`
	HasMapset           bool       `yaml:"has_mapset"`
	HasCustom           bool       `yaml:"has_custom"`

	// 扩展内容（运行时填充）
	ExtensionImports string
	ExtensionFields  string
}

type Config struct {
	Name       string          `yaml:"name"`
	PublicName string          `yaml:"public_name"`
	CacheTool  CacheToolConfig `yaml:"cache_tool"`
}

// CacheToolGenerator 聚合 cache_tool 代码生成器的所有方法
type CacheToolGenerator struct {
	config      Config
	cacheConfig CacheToolConfig
	template    *template.Template
}

// NewCacheToolGenerator 创建新的 CacheToolGenerator 实例
func NewCacheToolGenerator(configFile string) (*CacheToolGenerator, error) {
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config data: %v", err)
	}

	generator := &CacheToolGenerator{config: config}

	// 解析和适配配置
	err = generator.adaptConfig()
	if err != nil {
		return nil, err
	}

	// 处理字段
	generator.processFields()

	// 检查是否有自定义字段
	generator.cacheConfig.HasCustomField()

	// 处理扩展文件
	generator.loadExtensions()

	// 加载模板
	err = generator.loadTemplate()
	if err != nil {
		return nil, err
	}

	return generator, nil
}

// adaptConfig 适配配置结构
func (g *CacheToolGenerator) adaptConfig() error {
	if !g.config.CacheTool.Enabled {
		return fmt.Errorf("cache_tool is not enabled in configuration")
	}

	g.cacheConfig = g.config.CacheTool
	return nil
}

// processFields 处理字段配置，生成 CamelName 和 PublicCamelName
func (g *CacheToolGenerator) processFields() {
	for i := range g.cacheConfig.Fields {
		g.cacheConfig.Fields[i].CamelName = toCamel(g.cacheConfig.Fields[i].Name, false)
		if g.cacheConfig.Fields[i].PublicName != "" {
			g.cacheConfig.Fields[i].PublicCamelName = g.cacheConfig.Fields[i].PublicName
		} else {
			g.cacheConfig.Fields[i].PublicCamelName = toCamel(g.cacheConfig.Fields[i].Name, true)
		}
	}

	for i := range g.cacheConfig.KeyFields {
		g.cacheConfig.KeyFields[i].CamelName = toCamel(g.cacheConfig.KeyFields[i].Name, false)
		g.cacheConfig.KeyFields[i].PublicCamelName = g.cacheConfig.KeyFields[i].PublicName
	}
}

// loadTemplate 加载模板文件
func (g *CacheToolGenerator) loadTemplate() error {
	templateFile := "cache_tool.go.tpl"

	tmpl, err := template.New(templateFile).Funcs(template.FuncMap{
		"ToUpper":      toUpper,
		"toLowerCamel": toLowerCamel,
	}).ParseFiles(templateFile)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	g.template = tmpl
	return nil
}

// loadExtensions 加载扩展文件
func (g *CacheToolGenerator) loadExtensions() {
	extFile := g.config.Name + "_ext.go"
	if _, err := os.Stat(extFile); os.IsNotExist(err) {
		return // 扩展文件不存在
	}

	content, err := os.ReadFile(extFile)
	if err != nil {
		log.Printf("failed to read extension file %s: %v", extFile, err)
		return
	}

	extContent := string(content)

	// 提取导入部分
	g.cacheConfig.ExtensionImports = g.extractImports(extContent)

	// 提取字段部分
	g.cacheConfig.ExtensionFields = g.extractFields(extContent, g.config.PublicName)
}

// extractImports 提取扩展文件中的 import 部分
func (g *CacheToolGenerator) extractImports(content string) string {
	lines := strings.Split(content, "\n")
	var imports []string
	inImport := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import") {
			inImport = true
			continue
		}
		if inImport {
			if trimmed == ")" {
				break
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, "//") {
				imports = append(imports, "\t"+trimmed)
			}
		}
	}

	if len(imports) > 0 {
		return "\n" + strings.Join(imports, "\n")
	}
	return ""
}

// extractFields 提取扩展文件中的字段定义
func (g *CacheToolGenerator) extractFields(content, structName string) string {
	structStart := fmt.Sprintf("type %sExt struct", structName)
	lines := strings.Split(content, "\n")

	var fields []string
	inStruct := false
	braceCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(line, structStart) {
			inStruct = true
			if strings.Contains(line, "{") {
				braceCount = 1
			}
			continue
		}

		if inStruct {
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			if braceCount <= 0 {
				break
			}

			// 跳过空行和注释
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}

			// 添加字段（保持原有缩进格式）
			if !strings.Contains(trimmed, "func") && trimmed != "{" && trimmed != "}" {
				fields = append(fields, "\t"+trimmed)
			}
		}
	}
	if len(fields) > 0 {
		return "\n" + strings.Join(fields, "\n")
	}
	return ""
}

// Generate 生成代码文件
func (g *CacheToolGenerator) Generate() error {
	// 构造模板数据，合并基础配置和cache_tool配置
	templateData := struct {
		Name                string
		PublicName          string
		Fields              []Field
		KeyFields           []KeyField
		HasExtension        bool
		CollectionExtension bool
		HasMapset           bool
		HasCustom           bool
		ExtensionImports    string
		ExtensionFields     string
	}{
		Name:                g.config.Name,
		PublicName:          g.config.PublicName,
		Fields:              g.cacheConfig.Fields,
		KeyFields:           g.cacheConfig.KeyFields,
		HasExtension:        g.cacheConfig.HasExtension,
		CollectionExtension: g.cacheConfig.CollectionExtension,
		HasMapset:           g.cacheConfig.HasMapset,
		HasCustom:           g.cacheConfig.HasCustom,
		ExtensionImports:    g.cacheConfig.ExtensionImports,
		ExtensionFields:     g.cacheConfig.ExtensionFields,
	}

	var generatedCode bytes.Buffer
	err := g.template.Execute(&generatedCode, templateData)
	if err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	outputDir := "../cache/tool"
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}
	}

	outputFile := filepath.Join(outputDir, g.config.Name+".go")
	err = os.WriteFile(outputFile, generatedCode.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to write generated code to file: %v", err)
	}

	// 执行 go fmt 格式化生成的代码
	if err := formatGoFile(outputFile); err != nil {
		log.Printf("Warning: failed to format %s: %v", outputFile, err)
	}

	// 执行 goimports 格式化 import
	if err := formatImports(outputFile); err != nil {
		log.Printf("Warning: failed to format imports in %s: %v", outputFile, err)
	}

	fmt.Printf("Generated code for %s in %s\n", g.config.Name, outputFile)
	return nil
}

// HasCustomField 检查 CacheToolConfig 中是否有自定义字段
func (c *CacheToolConfig) HasCustomField() {
	for _, f := range c.Fields {
		if f.IsCustom {
			c.HasCustom = true
			return
		}
	}
}

// 工具函数
func toLowerCamel(s string) string {
	if s == "" {
		return ""
	}

	runes := []rune(s)
	i := 0
	for i < len(runes)-1 && unicode.IsUpper(runes[i]) && unicode.IsUpper(runes[i+1]) {
		runes[i] = unicode.ToLower(runes[i])
		i++
	}
	runes[i] = unicode.ToLower(runes[i])
	return string(runes)
}

func toCamel(s string, public bool) string {
	parts := strings.Split(s, "_")
	for i, part := range parts {
		if i == 0 && !public {
			parts[i] = strings.ToLower(part)
		} else {
			parts[i] = strings.Title(part)
		}
	}
	return strings.Join(parts, "")
}

func toUpper(s string) string {
	return strings.ToUpper(s)
}

// formatGoFile 使用 go fmt 格式化 Go 代码文件（通用工具函数）
func formatGoFile(filePath string) error {
	cmd := exec.Command("go", "fmt", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go fmt failed: %v, output: %s", err, string(output))
	}
	return nil
}

// formatImports 使用 goimports 格式化 import
func formatImports(filePath string) error {
	cmd := exec.Command("goimports", "-w", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("goimports failed: %v, output: %s", err, string(output))
	}
	return nil
}

// generateFromFiles 批量生成多个配置文件
func generateFromFiles(configFiles []string) error {
	var errors []string
	successCount := 0

	for _, configFile := range configFiles {
		fmt.Printf("Processing %s...\n", configFile)
		generator, err := NewCacheToolGenerator(configFile)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", configFile, err))
			continue
		}

		if err := generator.Generate(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", configFile, err))
			continue
		}
		successCount++
	}

	fmt.Printf("\nGeneration complete: %d success, %d failed\n", successCount, len(errors))

	if len(errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range errors {
			fmt.Printf("  - %s\n", err)
		}
		return fmt.Errorf("failed to generate %d files", len(errors))
	}

	return nil
}

// findConfigFiles 查找配置目录中的所有 yaml 文件
func findConfigFiles() ([]string, error) {
	configDir := "config"
	pattern := filepath.Join(configDir, "*.yaml")

	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to glob config files: %v", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no yaml files found in %s directory", configDir)
	}

	return files, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run generator.go <config_file>           # Generate single file")
		fmt.Println("  go run generator.go --all                   # Generate all config files")
		fmt.Println("  go run generator.go config/*.yaml           # Generate multiple files")
		return
	}

	arg := os.Args[1]

	// 批量生成所有配置文件
	if arg == "--all" {
		configFiles, err := findConfigFiles()
		if err != nil {
			log.Fatalf("failed to find config files: %v", err)
		}

		if err := generateFromFiles(configFiles); err != nil {
			log.Fatalf("batch generation failed: %v", err)
		}
		return
	}

	// 支持通配符模式或多个文件
	var configFiles []string
	if strings.Contains(arg, "*") || len(os.Args) > 2 {
		// 处理通配符或多个文件参数
		for _, pattern := range os.Args[1:] {
			if strings.Contains(pattern, "*") {
				matches, err := filepath.Glob(pattern)
				if err != nil {
					log.Fatalf("failed to glob pattern %s: %v", pattern, err)
				}
				configFiles = append(configFiles, matches...)
			} else {
				configFiles = append(configFiles, pattern)
			}
		}

		if err := generateFromFiles(configFiles); err != nil {
			log.Fatalf("batch generation failed: %v", err)
		}
		return
	}

	// 单个文件处理（保持原有兼容性）
	configFile := arg
	generator, err := NewCacheToolGenerator(configFile)
	if err != nil {
		log.Fatalf("failed to create generator: %v", err)
	}

	if err := generator.Generate(); err != nil {
		log.Fatalf("failed to generate code: %v", err)
	}
}
