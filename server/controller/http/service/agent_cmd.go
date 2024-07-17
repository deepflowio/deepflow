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

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/message/trident"
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
)

var (
	agentCommandTimeout = time.Second * 10

	agentCMDMutex   sync.RWMutex
	agentCMDManager = make(AgentCMDManager)
)

type AgentCMDManager map[string]*CMDManager

func GetAgentCMDManager(key string) *CMDManager {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		return manager
	}
	return nil
}

func AddToCMDManager(key string, requestID uint64) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	agentCMDManager[key] = &CMDManager{
		requestID: requestID,
		ExecCH:    make(chan *trident.RemoteExecRequest, 1),

		requestIDToResp: make(map[uint64]*CMDResp),
	}
}

func RemoveFromCMDManager(key string, requestID uint64) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		delete(manager.requestIDToResp, requestID)
		log.Infof("delete agent(key: %s, request id: %v) in manager", key, requestID)
	}
}

func RemoveAllFromCMDManager(key string) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		for requestID, cmdResp := range manager.requestIDToResp {
			errMessage := fmt.Sprintf("agent(key: %s) disconnected from the server", key)
			AppendErrorMessage(key, requestID, &errMessage)
			log.Error(errMessage)
			cmdResp.ExecDoneCH <- struct{}{}
		}
		delete(agentCMDManager, key)
		log.Infof("delete agent(key: %s) in manager", key)
	}
}

type CMDManager struct {
	requestID       uint64
	ExecCH          chan *trident.RemoteExecRequest
	requestIDToResp map[uint64]*CMDResp
}

type CMDResp struct {
	ExecDoneCH           chan struct{}
	RemoteCMDDoneCH      chan struct{}
	LinuxNamespaceDoneCH chan struct{}

	data *model.RemoteExecResp
}

func NewAgentCMDResp(key string) (uint64, *CMDResp) {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.requestID += 1
		resp := &CMDResp{
			ExecDoneCH:           make(chan struct{}, 1),
			RemoteCMDDoneCH:      make(chan struct{}, 1),
			LinuxNamespaceDoneCH: make(chan struct{}, 1),
			data:                 &model.RemoteExecResp{},
		}
		manager.requestIDToResp[manager.requestID] = resp
		return manager.requestID, resp
	}
	return 0, nil
}

func GetAgentCMDResp(key string, requestID uint64) *CMDResp {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		return manager.requestIDToResp[requestID]
	}
	return nil
}

func RemoveAgentCMDResp(key string, requestID uint64) {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		delete(manager.requestIDToResp, requestID)
	}
}

func GetRequestID(key string) uint64 {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		return manager.requestID
	}
	return 0
}

func AppendCommands(key string, requestID uint64, data []*trident.RemoteCommand) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.RemoteCommand = append(resp.data.RemoteCommand, data...)
		}
	}
}

func InitCommands(key string, requestID uint64, data []*trident.RemoteCommand) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.RemoteCommand = data
		}
	}
}

func AppendNamespaces(key string, requestID uint64, data []*trident.LinuxNamespace) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.LinuxNamespace = append(resp.data.LinuxNamespace, data...)
		}
	}
}

func InitNamespaces(key string, requestID uint64, data []*trident.LinuxNamespace) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.LinuxNamespace = data
		}
	}
}

func AppendContent(key string, requestID uint64, data []byte) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.Content += string(data)
		}
	}
}

func AppendErrorMessage(key string, requestID uint64, data *string) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.ErrorMessage = *data
		}
	}
}

func GetErrormessage(key string, requestID uint64) string {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.ErrorMessage
		}
	}
	return ""
}

func GetContent(key string, requestID uint64) string {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.Content
		}
	}
	return ""
}

func GetCommands(key string, requestID uint64) []*trident.RemoteCommand {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.RemoteCommand
		}
	}
	return nil
}

func GetNamespaces(key string, requestID uint64) []*trident.LinuxNamespace {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.LinuxNamespace
		}
	}
	return nil
}

func GetCMDAndNamespace(orgID, agentID int) (*model.RemoteExecResp, error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	var agent *mysql.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return nil, err
	}
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) get remote commands and linux namespaces",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name)

	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := NewAgentCMDResp(key)
	if manager == nil || cmdResp == nil {
		return nil, fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	defer RemoveAgentCMDResp(key, requestID)

	cmdReq := &trident.RemoteExecRequest{
		RequestId: &requestID,
		ExecType:  trident.ExecutionType_LIST_COMMAND.Enum(),
	}
	manager.ExecCH <- cmdReq

	timeout := time.After(agentCommandTimeout)
	resp := &model.RemoteExecResp{}
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout(%vs) to get remote commands and linux namespace", agentCommandTimeout.Seconds())
		case <-cmdResp.RemoteCMDDoneCH:
			resp.RemoteCommand = GetCommands(key, requestID)
			namespaceReq := &trident.RemoteExecRequest{RequestId: &requestID, ExecType: trident.ExecutionType_LIST_NAMESPACE.Enum()}
			manager.ExecCH <- namespaceReq
		case <-cmdResp.LinuxNamespaceDoneCH:
			resp.LinuxNamespace = GetNamespaces(key, requestID)
		case <-cmdResp.ExecDoneCH: // error occurred
			if len(GetCommands(key, requestID)) != 0 {
				return &model.RemoteExecResp{RemoteCommand: GetCommands(key, requestID)}, nil
			}
			log.Errorf("get agent(key: %s) remote commands error: %s", key, GetContent(key, requestID))
			return nil, errors.New(key)
		default:
			if len(GetCommands(key, requestID)) != 0 && len(GetNamespaces(key, requestID)) != 0 {
				log.Infof("len(commands)=%d, len(namespaces)=%d",
					len(GetCommands(key, requestID)), len(GetNamespaces(key, requestID)))
				return &model.RemoteExecResp{
					RemoteCommand:  GetCommands(key, requestID),
					LinuxNamespace: GetNamespaces(key, requestID),
				}, nil
			}
		}
	}
}

func RunAgentCMD(orgID, agentID int, req *trident.RemoteExecRequest, CMD string) (string, error) {
	serverLog := fmt.Sprintf("The deepflow-server is unable to execute the `%s` command."+
		" Detailed error information is as follows:\n\n", CMD)
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return "", fmt.Errorf("%s%s", serverLog, err.Error())
	}
	var agent *mysql.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return "", fmt.Errorf("%s%s", serverLog, err.Error())
	}
	b, _ := json.Marshal(req)
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) run remote command, request: %s",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, string(b))
	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := NewAgentCMDResp(key)
	if manager == nil || cmdResp == nil {
		return "", fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	defer RemoveAgentCMDResp(key, requestID)
	req.RequestId = &requestID
	manager.ExecCH <- req

	content := ""
	for {
		select {
		case <-time.After(agentCommandTimeout):
			return "", fmt.Errorf("%stimeout(%vs) to run agent command", serverLog, agentCommandTimeout.Seconds())
		case <-cmdResp.ExecDoneCH:
			if msg := GetErrormessage(key, requestID); msg != "" {
				return GetContent(key, requestID), fmt.Errorf("The deepflow-agent is unable to execute the `%s` command."+
					" Detailed error information is as follows:\n\n%s", CMD, msg)
			}
			content = GetContent(key, requestID)
			log.Infof("command run content len: %d", len(content))
			return content, nil
		}
	}
}
