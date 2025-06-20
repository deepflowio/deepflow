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

package mcp

import (
	"fmt"
	"os"

	"github.com/deepflowio/deepflow/server/mcp/config"
	"github.com/deepflowio/deepflow/server/mcp/handle"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	logging "github.com/op/go-logging"
)

var defaultRegion string
var log = logging.MustGetLogger("mcp")

type MCPServer struct {
	port   int
	server *server.MCPServer
}

func NewMCPServer(configPath string) *MCPServer {
	cfg := config.DefaultConfig()
	cfg.Load(configPath)

	mcpServer := server.NewMCPServer(
		"deepflow mcp server",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithRecovery(),
		server.WithLogging(),
	)

	mcpServer.AddTool(
		mcp.NewTool(
			"analyzeProfileData",
			mcp.WithDescription("分析指定 commitId 的 on-cpu profile 性能分析数据并生成报告"),
			mcp.WithString("commit_id"),
			mcp.WithString("start_time", mcp.DefaultString("0")),
			mcp.WithString("end_time", mcp.DefaultString("0")),
		), handle.FetchAndAnalyzeProfileData)

	return &MCPServer{
		port:   cfg.MCPConfig.ListenPort,
		server: mcpServer,
	}
}

func (s *MCPServer) Start() {
	log.Info("==================== Launching DeepFlow MCP Server ====================")

	httpServer := server.NewStreamableHTTPServer(s.server)
	if err := httpServer.Start(fmt.Sprintf(":%d", s.port)); err != nil {
		log.Errorf("failed to start mcp server: %s", err.Error())
		os.Exit(1)
	}
}
