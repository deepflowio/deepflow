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

package router

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
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
		"ps":              struct{}{},
		"java-dump-stack": struct{}{},
		"java-dump-gc":    struct{}{},
		"java-dump-heap":  struct{}{},
		"ebpf-dump-stack": struct{}{},
	}
	probeCommandMap = map[string]struct{}{
		"ping":       struct{}{},
		"tcpping":    struct{}{},
		"curl":       struct{}{},
		"dig":        struct{}{},
		"nslookup":   struct{}{},
		"traceroute": struct{}{},
	}
)

type AgentCMD struct{}

func NewAgentCMD() *AgentCMD {
	return new(AgentCMD)
}

func (c *AgentCMD) RegisterTo(e *gin.Engine) {
	agentRoutes := e.Group("/v1/agent/:id")
	agentRoutes.Use(AdminPermissionVerificationMiddleware())

	agentRoutes.GET("/cmd", forwardToServerConnectedByAgent(), getCMDAndNamespaceHandler)
	agentRoutes.POST("/cmd/run", forwardToServerConnectedByAgent(), cmdRunHandler)
}

func forwardToServerConnectedByAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		agentID, err := getAgentID(c)
		if err != nil {
			log.Error(err)
			BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			c.Abort()
			return
		}
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		db, err := mysql.GetDB(orgID.(int))
		if err != nil {
			log.Error(err)
			BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}
		var agent *mysql.VTap
		if err = db.Where("id = ?", agentID).First(&agent).Error; err != nil {
			log.Error(err)
			BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
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
				log.Error(err)
				BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
				return
			}
			forwardTimes = v
		} else {
			log.Infof("init %s to 0", ForwardControllerTimes)
			c.Request.Header.Set(ForwardControllerTimes, "0")
		}
		log.Infof("forward times: %d", forwardTimes)
		if forwardTimes > DefaultForwardControllerTimes {
			err := fmt.Errorf("get agent(name: %s, key: %s) commands forward times > %d", agent.Name, key, DefaultForwardControllerTimes)
			log.Error(err)
			BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}

		// get reverse proxy host
		newHost := common.NodeIP
		if common.NodeIP == agent.CurControllerIP {
			if manager := service.GetAgentCMDManager(key); manager != nil {
				c.Next()
				return
			} else {
				newHost = agent.ControllerIP
				c.Request.Header.Set(ForwardControllerTimes, fmt.Sprintf("%d", forwardTimes+1))
			}
		} else if common.NodeIP == agent.ControllerIP {
			if manager := service.GetAgentCMDManager(key); manager != nil {
				c.Next()
				return
			} else {
				newHost = agent.CurControllerIP
				c.Request.Header.Set(ForwardControllerTimes, fmt.Sprintf("%d", forwardTimes+1))
			}
		} else {
			newHost = agent.ControllerIP
			c.Request.Header.Set(ForwardControllerTimes, fmt.Sprintf("%d", forwardTimes+1))
		}

		reverseProxy := fmt.Sprintf("http://%s:%d", newHost, common.GConfig.HTTPNodePort)
		log.Infof("node ip(%s), reverse proxy(%s), agent current controller ip(%s), controller ip(%s)",
			common.NodeIP, reverseProxy, agent.CurControllerIP, agent.ControllerIP)

		proxyURL, err := url.Parse(reverseProxy)
		if err != nil {
			log.Error(err)
			BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}
		proxy := httputil.NewSingleHostReverseProxy(proxyURL)
		proxy.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

func getCMDAndNamespaceHandler(c *gin.Context) {
	agentID, err := getAgentID(c)
	if err != nil {
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}
	orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
	db, err := mysql.GetDB(orgID.(int))
	if err != nil {
		JsonResponse(c, nil, err)
		return
	}
	var agent *mysql.VTap
	if err = db.Where("id = ?", agentID).First(&agent).Error; err != nil {
		JsonResponse(c, nil, err)
		return
	}

	data, err := service.GetCMDAndNamespace(orgID.(int), agentID)
	if err != nil {
		JsonResponse(c, data, err)
		return
	}

	if filterCommandMap, ok := agentCommandMap[AgentCommandType(c.Query("type"))]; ok {
		var cmds []*trident.RemoteCommand
		for _, item := range data.RemoteCommand {
			if _, ok := filterCommandMap[*item.Cmd]; ok {
				cmds = append(cmds, item)
			}
		}
		data.RemoteCommand = cmds
		data.LinuxNamespace = nil

	}
	JsonResponse(c, data, nil)
}

func getAgentID(c *gin.Context) (int, error) {
	agentIDStr := c.Param("id")
	if agentIDStr == "" {
		return 0, errors.New("id can not be empty")
	}
	agentID, err := strconv.Atoi(agentIDStr)
	if err != nil {
		return 0, fmt.Errorf("agent id(%s) can not convert to int", agentIDStr)
	}
	return agentID, nil
}

func cmdRunHandler(c *gin.Context) {
	agentID, err := getAgentID(c)
	if err != nil {
		return
	}

	req := model.RemoteExecReq{}
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}
	agentReq := trident.RemoteExecRequest{
		ExecType: trident.ExecutionType_RUN_COMMAND.Enum(),
		// CommandId:    req.CommandId, // deprecated
		CommandIdent: req.CommandIdent,
		LinuxNsPid:   req.LinuxNsPid,
		Params:       req.Params,
	}

	orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
	content, err := service.RunAgentCMD(orgID.(int), agentID, &agentReq, req.CMD)
	if err != nil {
		InternalErrorResponse(c, content, httpcommon.SERVER_ERROR, err.Error())
		return
	}

	if req.OutputFormat.String() == trident.OutputFormat_TEXT.String() {
		JsonResponse(c, content, nil)
		return
	}
	sendAsFile(c, req.OutputFilename, bytes.NewBuffer([]byte(content)))
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
