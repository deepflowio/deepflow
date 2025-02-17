/**
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

package http

// import (
// 	"os"
// 	"path/filepath"

// 	"github.com/swaggo/swag"
// 	"github.com/swaggo/swag/gen"

// 	"github.com/deepflowio/deepflow/server/controller/common"
// )

// func generateSwaggerDocs() {
// 	// 获取程序运行目录
// 	exePath, err := os.Executable()
// 	if err != nil {
// 		log.Errorf("无法获取程序运行目录: %v", err)
// 	}
// 	exeDir := filepath.Dir(exePath)
// 	log.Infof(" TODO exeDir: %s", exeDir)

// 	// 获取当前文件目录
// 	curDir, err := os.Getwd()
// 	if err != nil {
// 		log.Errorf("无法获取当前文件目录: %v", err)
// 	}
// 	log.Infof(" TODO curDir: %s", curDir)

// 	// 设置 Swagger 文档生成路径
// 	searchDir := "controller/cmd/controller" // 当前目录
// 	outputDir := "controller/docs"

// 	// 生成 Swagger 文档
// 	err = gen.New().Build(&gen.Config{
// 		SearchDir:          searchDir,
// 		OutputDir:          outputDir,
// 		MainAPIFile:        filepath.Join(searchDir, "main.go"),
// 		PropNamingStrategy: "camelCase",
// 	})
// 	if err != nil {
// 		log.Errorf("无法生成 Swagger 文档: %v", err)
// 	}

// }
