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

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	grpcapi "github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	service "github.com/deepflowio/deepflow/server/controller/http/service/agent"
	"github.com/deepflowio/deepflow/server/controller/monitor/license"
)

const (
	ForwardControllerTimes        = "ForwardControllerTimes"
	DefaultForwardControllerTimes = 3

	AgentCommandTypeProbe   = AgentCommandType("probe")
	AgentCommandTypeProfile = AgentCommandType("profile")
)

type AgentCommandType string

var (
	agentCommandMap = map[AgentCommandType]map[string]struct{}{
		AgentCommandTypeProbe:   probeCommandMap,
		AgentCommandTypeProfile: profileCommandMap,
	}

	profileCommandMap = map[string]struct{}{
		"ps":              {},
		"java-dump-stack": {},
		"java-dump-gc":    {},
		"java-dump-heap":  {},
		"ebpf-dump-stack": {},
	}
	probeCommandMap = map[string]struct{}{
		"ping":       {},
		"tcping":     {},
		"curl":       {},
		"dig":        {},
		"traceroute": {},
	}
)

type AgentCMD struct {
	cfg *config.ControllerConfig
}

func NewAgentCMD(cfg *config.ControllerConfig) *AgentCMD {
	return &AgentCMD{
		cfg: cfg,
	}
}

func (a *AgentCMD) RegisterTo(e *gin.Engine) {
	agentRoutes := e.Group("/v1/agent/:id-or-name")

	agentRoutes.GET("/cmd", forwardToServerConnectedByAgent(), a.getCMDAndNamespaceHandler())
	agentRoutes.POST("/cmd/run", forwardToServerConnectedByAgent(), a.cmdRunHandler())
}

func forwardToServerConnectedByAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		db, err := metadb.GetDB(orgID.(int))
		if err != nil {
			log.Error(err, db.LogPrefixORGID)
			response.JSON(c, response.SetOptStatus(httpcommon.SERVER_ERROR), response.SetError(err))
			c.Abort()
			return
		}
		agentID, err := getAgentID(c, db)
		if err != nil {
			log.Error(err, db.LogPrefixORGID)
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			c.Abort()
			return
		}
		var agent *metadbmodel.VTap
		if err = db.Where("id = ?", agentID).First(&agent).Error; err != nil {
			log.Error(err, db.LogPrefixORGID)
			response.JSON(c, response.SetOptStatus(httpcommon.SERVER_ERROR), response.SetError(err))
			c.Abort()
			return
		}
		if err := license.GetChecker().CheckAgent(agent, common.AGENT_LICENSE_FUNCTION_LEGACY_PROBE); err != nil {
			log.Error(err, db.LogPrefixORGID)
			response.JSON(c, response.SetError(err))
			c.Abort()
			return
		}

		key := agent.CtrlIP + "-" + agent.CtrlMac
		// handle forward times
		var forwardTimes int
		timesStr := c.Request.Header.Get(ForwardControllerTimes)
		if len(timesStr) > 0 {
			v, err := strconv.Atoi(timesStr)
			if err != nil {
				log.Error(err, db.LogPrefixORGID)
				response.JSON(c, response.SetOptStatus(httpcommon.SERVER_ERROR), response.SetError(err))
				return
			}
			forwardTimes = v
		} else {
			log.Infof("agent(key: %s), node ip(%s) init %s to 0", key, common.NodeIP, ForwardControllerTimes, db.LogPrefixORGID)
			c.Request.Header.Set(ForwardControllerTimes, "0")
		}
		log.Infof("agent(key: %s), node ip(%s) forward times: %d", key, common.NodeIP, forwardTimes, db.LogPrefixORGID)
		if forwardTimes > DefaultForwardControllerTimes {
			err := fmt.Errorf("get agent(name: %s, key: %s) commands forward times > %d", agent.Name, key, DefaultForwardControllerTimes)
			log.Error(err, db.LogPrefixORGID)
			if common.GetOsType(agent.Os) == common.OS_WINDOWS {
				response.JSON(c, response.SetOptStatus(httpcommon.WINDOWS_AGENT_UNSUPPORTED), response.SetError(err))
			} else {
				response.JSON(c, response.SetOptStatus(httpcommon.AGENT_UNSUPPORTED), response.SetError(err))
			}
			c.Abort()
			return
		}

		log.Infof("agent(key: %s), node ip(%s), agent cur controller ip(%s), controller ip(%s)",
			key, common.NodeIP, agent.CurControllerIP, agent.ControllerIP)
		// get reverse proxy host
		newHost := common.NodeIP
		if newHost != agent.CurControllerIP && newHost != agent.ControllerIP {
			newHost = agent.ControllerIP
			c.Request.Header.Set(ForwardControllerTimes, fmt.Sprintf("%d", forwardTimes+1))
		} else {
			manager := service.GetAgentCMDManager(key)
			if manager != nil && manager.IsValid() {
				c.Next()
				return
			}

			log.Infof("agent(key: %s) cmd manager not found in server(ip: %s), lookup next", key, common.NodeIP)
			if newHost == agent.CurControllerIP {
				newHost = agent.ControllerIP
			} else {
				newHost = agent.CurControllerIP
			}
			c.Request.Header.Set(ForwardControllerTimes, fmt.Sprintf("%d", forwardTimes+1))
		}

		reverseProxy := fmt.Sprintf("http://%s:%d", newHost, common.GConfig.HTTPNodePort)
		log.Infof("agent(key: %s), node ip(%s), reverse proxy(%s), agent current controller ip(%s), controller ip(%s)",
			key, common.NodeIP, reverseProxy, agent.CurControllerIP, agent.ControllerIP, db.LogPrefixORGID)

		proxyURL, err := url.Parse(reverseProxy)
		if err != nil {
			log.Error(err, db.LogPrefixORGID)
			response.JSON(c, response.SetOptStatus(httpcommon.SERVER_ERROR), response.SetError(err))
			c.Abort()
			return
		}
		proxy := httputil.NewSingleHostReverseProxy(proxyURL)
		proxy.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

func (a *AgentCMD) getCMDAndNamespaceHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		db, err := metadb.GetDB(orgID.(int))
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		agentID, err := getAgentID(c, db)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}
		var agent *metadbmodel.VTap
		if err = db.Where("id = ?", agentID).First(&agent).Error; err != nil {
			response.JSON(c, response.SetError(err))
			return
		}

		data, err := service.GetCMDAndNamespace(a.cfg.AgentCommandTimeout, orgID.(int), agentID)
		if err != nil {
			response.JSON(c, response.SetData(data), response.SetError(err))
			return
		}

		userType, _ := c.Get(common.HEADER_KEY_X_USER_TYPE)
		if !(userType == common.USER_TYPE_SUPER_ADMIN || userType == common.USER_TYPE_ADMIN) {
			var cmds []*grpcapi.RemoteCommand
			for _, item := range data.RemoteCommands {
				_, ok1 := profileCommandMap[*item.Cmd]
				_, ok2 := probeCommandMap[*item.Cmd]
				if ok1 || ok2 {
					cmds = append(cmds, item)
				}
			}
			data.RemoteCommands = cmds
		}

		if filterCommandMap, ok := agentCommandMap[AgentCommandType(c.Query("type"))]; ok {
			var cmds []*grpcapi.RemoteCommand
			for _, item := range data.RemoteCommands {
				if item.Cmd == nil {
					continue
				}
				if _, ok := filterCommandMap[*item.Cmd]; ok {
					cmds = append(cmds, item)
				}
			}
			data.RemoteCommands = cmds
			data.LinuxNamespaces = nil

		}
		response.JSON(c, response.SetData(data))
	}
}

func getAgentID(c *gin.Context, db *metadb.DB) (int, error) {
	agentIDentStr := c.Param("id-or-name")
	if agentIDentStr == "" {
		return 0, errors.New("ident can not be empty")
	}
	agentID, err := strconv.Atoi(agentIDentStr)
	if err != nil {
		var agent metadbmodel.VTap
		if err := db.Where("name = ?", agentIDentStr).First(&agent).Error; err != nil {
			return 0, fmt.Errorf("failed to get agent by name(%s), error: %s", err.Error())
		}
		return agent.ID, nil
	}
	return agentID, nil
}

func (a *AgentCMD) cmdRunHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		req := service.RemoteExecReq{}
		if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}
		// Profile commands and probe commands are available to everyone.
		userType, _ := c.Get(common.HEADER_KEY_X_USER_TYPE)
		if !(userType == common.USER_TYPE_SUPER_ADMIN || userType == common.USER_TYPE_ADMIN) {
			_, ok1 := profileCommandMap[req.CMD]
			_, ok2 := probeCommandMap[req.CMD]
			if !(ok1 || ok2) {
				response.JSON(c, response.SetOptStatus(httpcommon.NO_PERMISSIONS), response.SetError(fmt.Errorf("only super admin and admin can operate command(%s)", req.CMD)))
				return
			}
		}

		agentReq := grpcapi.RemoteExecRequest{
			ExecType: grpcapi.ExecutionType_RUN_COMMAND.Enum(),
			// CommandId:    req.CommandId, // deprecated
			CommandIdent: req.CommandIdent,
			LinuxNsPid:   req.LinuxNsPid,
			Params:       req.Params,
		}

		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		db, err := metadb.GetDB(orgID.(int))
		if err != nil {
			response.JSON(c, response.SetError(err))
			return
		}
		agentID, err := getAgentID(c, db)
		if err != nil {
			response.JSON(c, response.SetOptStatus(httpcommon.INVALID_PARAMETERS), response.SetError(err))
			return
		}
		content, err := service.RunAgentCMD(a.cfg.AgentCommandTimeout, orgID.(int), agentID, &agentReq, req.CMD)
		if err != nil {
			response.JSON(c, response.SetData(content), response.SetOptStatus(httpcommon.SERVER_ERROR), response.SetError(err))
			return
		}

		if req.OutputFormat.String() == grpcapi.OutputFormat_TEXT.String() {
			response.JSON(c, response.SetData(content))
			return
		}
		sendAsFile(c, req.OutputFilename, bytes.NewBuffer([]byte(content)))
	}
}

func sendAsFile(c *gin.Context, fileName string, content *bytes.Buffer) {
	c.Writer.Header().Set("Content-Type", "application/octet-stream")
	if fileName != "" {
		c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=utf-8''%s", fileName))
	}

	if _, err := io.Copy(c.Writer, content); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		log.Error(err)
		return
	}
}
