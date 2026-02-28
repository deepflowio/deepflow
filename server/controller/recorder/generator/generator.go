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

// RefConfig 统一的外键引用配置（使用 small_snake_case 值，运行时转换为 PascalCase）
type RefConfig struct {
	Resource string `yaml:"resource"`
	LookupBy string `yaml:"lookup_by"`
	Target   string `yaml:"target"`
}

type Field struct {
	Name          string     `yaml:"name"`
	OrmName       string     `yaml:"orm_name"`
	Type          string     `yaml:"type"`
	Of            string     `yaml:"of"`              // 集合元素类型，配合 type: set 使用
	ForValidation bool       `yaml:"for_validation"`
	ForIndex      bool       `yaml:"for_index"`
	ForMutation   bool       `yaml:"for_mutation"`
	IsExtension   bool       `yaml:"is_extension"`
	Ref           *RefConfig `yaml:"ref"`
	Comment       string     `yaml:"comment"`

	// 运行时填充
	CamelName       string
	PublicCamelName string
	IsSet           bool   // 运行时从 type == "set" 推导
	GoType          string // 运行时生成的实际 Go 类型
	RefResource     string // 运行时 toCamel(ref.resource)
	RefLookupBy     string // 运行时 toCamel(ref.lookup_by)
	RefTarget       string // 运行时 toCamel(ref.target)
}

// KeyField 运行时从 fields 中 for_index=true 的字段推导生成
type KeyField struct {
	Name            string
	Type            string
	CamelName       string
	PublicCamelName string
}

// DiffbaseField cache_diffbase 中的字段定义
type DiffbaseField struct {
	Name        string     `yaml:"name"`
	OrmName     string     `yaml:"orm_name"`
	Type        string     `yaml:"type"`
	Of          string     `yaml:"of"`            // 集合元素类型，配合 type: list 使用
	From        string     `yaml:"from"`           // 数据源类型转换，如 bytes
	IsLarge     bool       `yaml:"is_large"`       // 是否为大字段（日志输出时隐藏）
	IsExtension bool       `yaml:"is_extension"`   // 是否为扩展字段（reset 中跳过，由 resetExt 处理）
	Ref         *RefConfig `yaml:"ref"`
	Comment     string     `yaml:"comment"`

	// 运行时填充
	CamelName       string
	PublicCamelName string
	IsList          bool   // 运行时从 type == "list" 推导
	GoType          string // 运行时生成的实际 Go 类型
	RefResource     string // 运行时 toCamel(ref.resource)
	RefLookupBy     string // 运行时 toCamel(ref.lookup_by)
	RefTarget       string // 运行时 toCamel(ref.target)
}

type CacheToolConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Fields     []Field  `yaml:"fields"`
	Extensions []string `yaml:"extensions"`

	// 以下字段均在运行时从配置推导，不从 YAML 读取
	KeyFields           []KeyField
	HasStructExtension  bool
	CollectionExtension bool
	HasMapset           bool
	HasExtensionField   bool

	// 扩展内容（运行时填充）
	ExtensionImports string
	ExtensionFields  string
}

type CacheDiffbaseConfig struct {
	Enabled    bool            `yaml:"enabled"`
	Fields     []DiffbaseField `yaml:"fields"`
	Extensions []string        `yaml:"extensions"`

	// 运行时推导
	HasStructExtension bool
	HasExtensionField  bool
	HasLargeField      bool
}

type Config struct {
	Name      string          `yaml:"name"`
	OrmName   string          `yaml:"orm_name"`
	CacheTool CacheToolConfig `yaml:"cache_tool"`
	CacheDiffbase CacheDiffbaseConfig `yaml:"cache_diffbase"`

	PublicName string // 运行时生成
}

// CacheToolGenerator 聚合 cache_tool 代码生成器的所有方法
type CacheToolGenerator struct {
	config      Config
	cacheConfig CacheToolConfig
	template    *template.Template
}

// CacheDiffbaseGenerator 聚合 cache_diffbase 代码生成器的所有方法
type CacheDiffbaseGenerator struct {
	config         Config
	diffbaseConfig CacheDiffbaseConfig
	template       *template.Template
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

	// 从字段和 extensions 推导运行时标志
	generator.deriveFlags()

	// 处理扩展文件
	generator.loadExtensions()

	// 加载模板
	err = generator.loadTemplate()
	if err != nil {
		return nil, err
	}

	return generator, nil
}

// NewCacheDiffbaseGenerator 创建新的 CacheDiffbaseGenerator 实例
func NewCacheDiffbaseGenerator(configFile string) (*CacheDiffbaseGenerator, error) {
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config data: %v", err)
	}

	generator := &CacheDiffbaseGenerator{config: config}

	// 解析和适配配置
	err = generator.adaptConfig()
	if err != nil {
		return nil, err
	}

	// 处理字段
	generator.processFields()

	// 从字段和 extensions 配置推导运行时标志
	generator.deriveFlags()

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

	// 自动从 snake_case Name 生成 UpperCamelCase PublicName
	g.config.PublicName = toCamel(g.config.Name, true)

	if g.config.OrmName == "" {
		return fmt.Errorf("orm_name is required in configuration")
	}

	g.cacheConfig = g.config.CacheTool
	return nil
}

// processFields 处理字段配置，生成 CamelName、PublicCamelName、GoType 和 Ref 运行时字段
func (g *CacheToolGenerator) processFields() {
	for i := range g.cacheConfig.Fields {
		f := &g.cacheConfig.Fields[i]
		f.CamelName = toCamel(f.Name, false)
		f.PublicCamelName = toCamel(f.Name, true)

		// 处理 set 类型
		if f.Type == "set" {
			f.IsSet = true
			f.GoType = "mapset.Set[" + f.Of + "]"
		} else {
			f.GoType = f.Type
		}

		processRefConfig(f.Ref, &f.RefResource, &f.RefLookupBy, &f.RefTarget)
	}
}

// deriveFlags 从 fields 和 extensions 配置推导运行时标志
func (g *CacheToolGenerator) deriveFlags() {
	// 从 extensions 列表推导 HasStructExtension 和 CollectionExtension
	for _, ext := range g.cacheConfig.Extensions {
		switch ext {
		case "struct":
			g.cacheConfig.HasStructExtension = true
		case "collection":
			g.cacheConfig.CollectionExtension = true
		}
	}

	// 从 fields 推导 KeyFields、HasMapset、HasExtensionField
	for _, f := range g.cacheConfig.Fields {
		if f.ForIndex {
			g.cacheConfig.KeyFields = append(g.cacheConfig.KeyFields, KeyField{
				Name:            f.Name,
				Type:            f.Type,
				CamelName:       f.CamelName,
				PublicCamelName: f.PublicCamelName,
			})
		}
		if f.IsSet {
			g.cacheConfig.HasMapset = true
		}
		if f.IsExtension {
			g.cacheConfig.HasExtensionField = true
		}
	}
}

// loadTemplate 加载模板文件
func (g *CacheToolGenerator) loadTemplate() error {
	templateFile := "../cache/tool/gen.go.tpl"
	templateName := filepath.Base(templateFile)

	tmpl, err := template.New(templateName).Funcs(template.FuncMap{
		"ToUpper":      toUpper,
		"toLowerCamel": toLowerCamel,
		"hasSuffix":    strings.HasSuffix,
		"trimPrefix":   strings.TrimPrefix, // 注册 trimPrefix 函数
	}).ParseFiles(templateFile)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	g.template = tmpl
	return nil
}

// loadExtensions 加载扩展文件
func (g *CacheToolGenerator) loadExtensions() {
	extFile := filepath.Join("../cache/tool", g.config.Name+"_ext.go")
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
		OrmName             string
		Fields              []Field
		KeyFields           []KeyField
		HasStructExtension  bool
		CollectionExtension bool
		HasMapset           bool
		HasExtensionField   bool
		ExtensionImports    string
		ExtensionFields     string
	}{
		Name:                g.config.Name,
		PublicName:          g.config.PublicName,
		OrmName:             g.config.OrmName,
		Fields:              g.cacheConfig.Fields,
		KeyFields:           g.cacheConfig.KeyFields,
		HasStructExtension:  g.cacheConfig.HasStructExtension,
		CollectionExtension: g.cacheConfig.CollectionExtension,
		HasMapset:           g.cacheConfig.HasMapset,
		HasExtensionField:   g.cacheConfig.HasExtensionField,
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

	fmt.Printf("Generated code for %s in %s\n", g.config.Name, outputFile)
	return nil
}

// CacheDiffbaseGenerator 的方法实现

// adaptConfig 适配配置结构
func (g *CacheDiffbaseGenerator) adaptConfig() error {
	if !g.config.CacheDiffbase.Enabled {
		return fmt.Errorf("cache_diffbase is not enabled in configuration")
	}

	// 自动从 snake_case Name 生成 UpperCamelCase PublicName
	g.config.PublicName = toCamel(g.config.Name, true)

	if g.config.OrmName == "" {
		return fmt.Errorf("orm_name is required in configuration")
	}

	g.diffbaseConfig = g.config.CacheDiffbase
	return nil
}

// processFields 处理字段配置，生成 CamelName、PublicCamelName 和 GoType
func (g *CacheDiffbaseGenerator) processFields() {
	for i := range g.diffbaseConfig.Fields {
		f := &g.diffbaseConfig.Fields[i]
		f.CamelName = toCamel(f.Name, false)
		f.PublicCamelName = toCamel(f.Name, true)

		// 处理 list 类型
		if f.Type == "list" {
			f.IsList = true
			f.GoType = "[]" + f.Of
		} else {
			f.GoType = f.Type
		}

		// 处理 ref 配置，转换为 PascalCase
		processRefConfig(f.Ref, &f.RefResource, &f.RefLookupBy, &f.RefTarget)

		// 推导 HasExtensionField 和 HasLargeField
		if f.IsExtension {
			g.diffbaseConfig.HasExtensionField = true
		}
		if f.IsLarge {
			g.diffbaseConfig.HasLargeField = true
		}
	}
}

// deriveFlags 从 extensions 配置推导运行时标志
func (g *CacheDiffbaseGenerator) deriveFlags() {
	for _, ext := range g.diffbaseConfig.Extensions {
		switch ext {
		case "struct":
			g.diffbaseConfig.HasStructExtension = true
		}
	}
}

// loadTemplate 加载模板文件
func (g *CacheDiffbaseGenerator) loadTemplate() error {
	templateFile := "../cache/diffbase/gen.go.tpl"
	templateName := filepath.Base(templateFile)

	tmpl, err := template.New(templateName).Funcs(template.FuncMap{
		"ToUpper":      toUpper,
		"toLowerCamel": toLowerCamel,
		"hasSuffix":    strings.HasSuffix,
		"trimPrefix":   strings.TrimPrefix, // 注册 trimPrefix 函数
	}).ParseFiles(templateFile)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	g.template = tmpl
	return nil
}

// Generate 生成代码文件
func (g *CacheDiffbaseGenerator) Generate() error {
	// 构造模板数据
	templateData := struct {
		Name               string
		PublicName         string
		OrmName            string
		Fields             []DiffbaseField
		HasStructExtension bool
		HasExtensionField  bool
		HasLargeField      bool
	}{
		Name:               g.config.Name,
		PublicName:         g.config.PublicName,
		OrmName:            g.config.OrmName,
		Fields:             g.diffbaseConfig.Fields,
		HasStructExtension: g.diffbaseConfig.HasStructExtension,
		HasExtensionField:  g.diffbaseConfig.HasExtensionField,
		HasLargeField:      g.diffbaseConfig.HasLargeField,
	}

	var generatedCode bytes.Buffer
	err := g.template.Execute(&generatedCode, templateData)
	if err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	outputDir := "../cache/diffbase"
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

	fmt.Printf("Generated diffbase code for %s in %s\n", g.config.Name, outputFile)
	return nil
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

// processRefConfig 将 ref 配置的 snake_case 值转换为 PascalCase 运行时字段（公共方法）
func processRefConfig(ref *RefConfig, refResource, refLookupBy, refTarget *string) {
	if ref == nil {
		return
	}
	*refResource = toCamel(ref.Resource, true)
	*refLookupBy = toCamel(ref.LookupBy, true)
	*refTarget = toCamel(ref.Target, true)
}

// formatGoFile 使用 go fmt  格式化 Go 代码文件（通用工具函数）,使用 goimports 格式化 import
func formatGoFile(filePath string) error {
	// 设置 go fmt  命令
	cmd := exec.Command("go", "fmt", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go fmt failed: %v, output: %s", err, string(output))
	}

	// 设置 goimports 命令
	cmd = exec.Command("goimports", "-w", filePath)
	output, err = cmd.CombinedOutput()
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

		// 读取配置文件判断启用了哪些生成器
		configData, err := os.ReadFile(configFile)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: failed to read config: %v", configFile, err))
			continue
		}

		var config Config
		err = yaml.Unmarshal(configData, &config)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: failed to unmarshal config: %v", configFile, err))
			continue
		}

		// 生成 cache_tool
		if config.CacheTool.Enabled {
			generator, err := NewCacheToolGenerator(configFile)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (cache_tool): %v", configFile, err))
			} else if err := generator.Generate(); err != nil {
				errors = append(errors, fmt.Sprintf("%s (cache_tool): %v", configFile, err))
			} else {
				successCount++
			}
		}

		// 生成 cache_diffbase
		if config.CacheDiffbase.Enabled {
			generator, err := NewCacheDiffbaseGenerator(configFile)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s (cache_diffbase): %v", configFile, err))
			} else if err := generator.Generate(); err != nil {
				errors = append(errors, fmt.Sprintf("%s (cache_diffbase): %v", configFile, err))
			} else {
				successCount++
			}
		}
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
	configDir := "../generator_config"
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
		fmt.Println("  go run generator.go <config_file>                    # Generate single file")
		fmt.Println("  go run generator.go --all                            # Generate all config files")
		fmt.Println("  go run generator.go ../generator_config/*.yaml       # Generate multiple files")
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

	// 单个文件处理（保持原有兼容性，但使用统一的生成逻辑）
	configFile := arg
	if err := generateFromFiles([]string{configFile}); err != nil {
		log.Fatalf("generation failed: %v", err)
	}
}
