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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	routercommon "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

var ForwardTimes = 3

type AgentCMD struct{}

func NewAgentCMD() *AgentCMD {
	return new(AgentCMD)
}

func (c *AgentCMD) RegisterTo(e *gin.Engine) {
	e.GET("/v1/agent/:id/cmd", getCMDAndNamespaceHandler)
	e.POST("/v1/agent/:id/cmd/run", cmdRunHandler)
}

const (
	ForwardControllerTimes        = "ForwardControllerTimes"
	DefaultForwardControllerTimes = 3
)

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

	handleFunc := func() {
		data, err := service.GetCMDAndNamespace(orgID.(int), agentID)
		// if errors.Is(err, httpcommon.ERR_NO_AGENT_REMOTE_EXEC_CONNECT) {
		// 	c.Set("error", httpcommon.ERR_NO_AGENT_REMOTE_EXEC_CONNECT)
		// 	return
		// }
		JsonResponse(c, data, err)
	}

	handleIfNeedForward(c, agent, handleFunc)
}

func handleIfNeedForward(c *gin.Context, agent *mysql.VTap, handleFunc func()) {
	key := agent.CtrlIP + "-" + agent.CtrlMac

	b1, _ := json.Marshal(c.Request.Header)
	log.Infof("weiqiang req Header: %s", string(b1))
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
		log.Infof("current forward times: %d", forwardTimes)
		c.Request.Header.Set(ForwardControllerTimes, fmt.Sprintf("%d", v+1))
	} else {
		log.Infof("init %s to 0", ForwardControllerTimes)
		c.Request.Header.Set(ForwardControllerTimes, "0")
	}
	log.Infof("weiqiang forward times: %d", forwardTimes)
	if forwardTimes > DefaultForwardControllerTimes {
		err := fmt.Errorf("get agent(name: %s, key: %s) commands forward time > %d", agent.Name, key, DefaultForwardControllerTimes)
		log.Error(err)
		BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
		return
	}

	if common.NodeIP == agent.CurControllerIP {
		if ok := service.IsAgentHealth(key); ok {
			handleFunc()
		} else {
			c.Set(ForwardControllerTimes, forwardTimes+1)
			routercommon.ForwardToController(c, agent.ControllerIP, common.GConfig.HTTPNodePort)
		}
		return
	} else if common.NodeIP == agent.ControllerIP {
		if ok := service.IsAgentHealth(key); ok {
			handleFunc()
		} else {
			c.Set(ForwardControllerTimes, forwardTimes+1)
			routercommon.ForwardToController(c, agent.CurControllerIP, common.GConfig.HTTPNodePort)
		}
		return
	} else {
		c.Set(ForwardControllerTimes, forwardTimes+1)
		routercommon.ForwardToController(c, agent.CurControllerIP, common.GConfig.HTTPNodePort)
		return
	}
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
		log.Error(err)
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
		return
	}
	b, _ := json.Marshal(req)
	log.Infof("command run request: %s", string(b))

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

	agentReq := trident.RemoteExecRequest{
		ExecType:   trident.ExecutionType_RUN_COMMAND.Enum(),
		CommandId:  req.CommandId,
		LinuxNsPid: req.LinuxNsPid,
		Params:     req.Params,
	}

	handleFunc := func() {
		content, err := service.RunAgentCMD(orgID.(int), agentID, &agentReq)
		if err != nil {
			BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			return
		}
		if req.OutputFormat.String() == trident.OutputFormat_TEXT.String() {
			JsonResponse(c, content, nil)
			return
		}
		sendAsFile(c, req.OutputFilename, bytes.NewBuffer([]byte(content)))
	}
	handleIfNeedForward(c, agent, handleFunc)
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
