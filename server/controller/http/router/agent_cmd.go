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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

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
	e.GET("/v1/agent/:id/cmd", forwardToServerConnectedByAgent(), getCMDAndNamespaceHandler)
	e.POST("/v1/agent/:id/cmd/run", forwardToServerConnectedByAgent(), cmdRunHandler)
}

func forwardToServerConnectedByAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		agentID, err := getAgentID(c)
		if err != nil {
			log.Error(err)
			routercommon.BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
			c.Abort()
			return
		}
		orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
		db, err := mysql.GetDB(orgID.(int))
		if err != nil {
			log.Error(err)
			routercommon.BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}

		var agent *mysql.VTap
		if err = db.Where("id = ?", agentID).First(&agent).Error; err != nil {
			log.Error(err)
			routercommon.BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}
		key := agent.CtrlIP + "-" + agent.CtrlMac
		_, ok := service.AgentRemoteExecMap[key]
		if ok {
			c.Next()
			return
		}
		count := c.GetInt("ForwardTimes")
		if count >= ForwardTimes {
			err := fmt.Errorf("forward times >= 5, can not find stream with aget remote exec")
			log.Error(err)
			routercommon.BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}
		c.Set("ForwardTimes", count+1)

		ip, _ := getTargetIP(c.Request.Host)
		log.Infof("weiqiang host: %v, ip: %v, url host: %v", c.Request.Host, ip, c.Request.URL.Host)

		newHost, newPort, err := getTargetServerURL(db, agent)
		if err != nil {
			log.Error(err)
			routercommon.BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}
		targetURL := fmt.Sprintf("http://%s:%d", newHost, newPort)

		log.Infof("weiqiang agent, targetURL(%s), current controller ip(%s), controller ip(%s)", targetURL, agent.CurControllerIP, agent.ControllerIP)

		proxyURL, err := url.Parse(targetURL)
		if err != nil {
			log.Error(err)
			routercommon.BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
			c.Abort()
			return
		}
		log.Infof("weiqiang host(%s) proxy(%s)", proxyURL.String())
		proxy := httputil.NewSingleHostReverseProxy(proxyURL)

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func getTargetIP(host string) (string, error) {
	var ip string
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Error(err)
			return "", err
		}
		log.Infof("weiqiang ips: %#v", ips)
		if len(ips) == 0 {
			return "", fmt.Errorf("net parse ip null, host(%s)", host)
		}
		b, _ := json.Marshal(ips)
		log.Infof("weiqiang ips: %v", string(b))
		ip = ips[0].String()
	} else {
		if !strings.Contains(host, ":") {
			ip = host
		} else {
			hostIP, _, err := net.SplitHostPort(host)
			if err != nil {
				return "", err
			}
			log.Infof("weiqiang host ip: %v", hostIP)
			ip = hostIP
		}
	}
	return ip, nil
}

func getTargetServerURL(db *mysql.DB, agent *mysql.VTap) (string, int, error) {
	newHost, newPort := agent.CurControllerIP, common.GConfig.HTTPNodePort

	key := agent.CtrlIP + "-" + agent.CtrlMac
	if common.NodeIP == agent.CurControllerIP {
		newHost = agent.CurControllerIP
		if _, ok := service.AgentRemoteExecMap[key]; !ok {
			newHost = agent.ControllerIP
		}
	} else if common.NodeIP == agent.ControllerIP {
		newHost = agent.ControllerIP
		if _, ok := service.AgentRemoteExecMap[key]; !ok {
			newHost = agent.CurControllerIP
		}
	} else {
		log.Infof("weiqiang node ip(%s)", common.NodeIP)
	}

	return newHost, newPort, nil
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
	if errors.Is(err, httpcommon.ERR_NO_AGENT_REMOTE_EXEC_CONNECT) {
		c.Set("error", httpcommon.ERR_NO_AGENT_REMOTE_EXEC_CONNECT)
		return
	}
	JsonResponse(c, data, err)
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
	// TODO(weiqiang): delete
	b, _ := json.Marshal(c.Request.Header)
	log.Infof("request header: %s", string(b))

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
		ExecType:   trident.ExecutionType_RUN_COMMAND.Enum(),
		CommandId:  req.CommandId,
		LinuxNsPid: req.LinuxNsPid,
		Params:     req.Params,
	}

	// commandIDStr := c.PostForm("command_id")
	// log.Infof("weiqiang commandIDStr: %v", commandIDStr)
	// commandID, err := strconv.Atoi(commandIDStr)
	// if err != nil {
	// 	log.Error(err)
	// 	BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
	// 	return
	// }
	// agentReq.CommandId = proto.Uint32(uint32(commandID))

	// var nsPID int
	// nsPIDStr := c.PostForm("linux_ns_pid")
	// if len(nsPIDStr) > 0 {
	// 	nsPID, err = strconv.Atoi(nsPIDStr)
	// 	if err != nil {
	// 		log.Error(err)
	// 		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
	// 		return
	// 	}
	// 	agentReq.LinuxNsPid = proto.Uint32(uint32(nsPID))
	// }

	// var params []*trident.Parameter
	// paramStr := c.PostForm("params")
	// if len(paramStr) > 0 {
	// 	if err = json.Unmarshal([]byte(paramStr), &params); err != nil {
	// 		log.Error(err)
	// 		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
	// 		return
	// 	}
	// 	agentReq.Params = params
	// }

	// outputFormatStr, ok := c.GetPostForm("output_format")
	// if !ok {
	// 	BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, fmt.Sprintf("output_format can not empty"))
	// 	return
	// }
	// outputFormat, err := strconv.Atoi(outputFormatStr)
	// if err != nil {
	// 	log.Error(err)
	// 	BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, err.Error())
	// 	return
	// }

	// var outputFilename string
	// if outputFormat == int(trident.OutputFormat_BINARY) {
	// 	outputFilename, ok = c.GetPostForm("output_filename")
	// 	if !ok {
	// 		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS,
	// 			fmt.Sprintf("output_filename can not empty when output_format is binary"))
	// 		return
	// 	}
	// }

	orgID, _ := c.Get(common.HEADER_KEY_X_ORG_ID)
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
