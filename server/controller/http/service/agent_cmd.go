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
	"fmt"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/message/trident"
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/model"
)

var (
	agentCommandTimeout = time.Minute

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
	m := initCMDManager(requestID)
	agentCMDManager[key] = m
}

func RemoveFromCMDManager(key string) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if _, ok := agentCMDManager[key]; ok {
		delete(agentCMDManager, key)
		log.Infof("delete agent(key:%s) in manager", key)
	}
}

func initCMDManager(requestID uint64) *CMDManager {
	m := &CMDManager{
		ExecCH:               make(chan *trident.RemoteExecRequest, 1),
		ExecDoneCH:           make(chan struct{}, 1),
		RemoteCMDDoneCH:      make(chan struct{}, 1),
		LinuxNamespaceDoneCH: make(chan struct{}, 1),

		requestID: requestID,
		resp:      &model.RemoteExecResp{},
	}
	return m
}

type CMDManager struct {
	ExecCH               chan *trident.RemoteExecRequest
	ExecDoneCH           chan struct{}
	RemoteCMDDoneCH      chan struct{}
	LinuxNamespaceDoneCH chan struct{}

	requestID uint64
	resp      *model.RemoteExecResp
}

func resetResp(key string) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.resp = &model.RemoteExecResp{}
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

func SetRequestID(key string, requestID uint64) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.requestID = requestID
	}
}

func AppendCommands(key string, data []*trident.RemoteCommand) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.resp.RemoteCommand = append(manager.resp.RemoteCommand, data...)
	}
}

func InitCommands(key string, data []*trident.RemoteCommand) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.resp.RemoteCommand = data
	}
}

func AppendNamespaces(key string, data []*trident.LinuxNamespace) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.resp.LinuxNamespace = append(manager.resp.LinuxNamespace, data...)
	}
}

func InitNamespaces(key string, data []*trident.LinuxNamespace) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.resp.LinuxNamespace = data
	}
}

func AppendContent(key string, data []byte) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.resp.Content += string(data)
	}
}

func AppendErr(key string, data *string) {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if manager, ok := agentCMDManager[key]; ok {
		manager.resp.Content += *data
	}
}

func GetContent(key string) string {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		return manager.resp.Content
	}
	return ""
}

func GetCommands(key string) []*trident.RemoteCommand {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		return manager.resp.RemoteCommand
	}
	return nil
}

func GetNamespaces(key string) []*trident.LinuxNamespace {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		return manager.resp.LinuxNamespace
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
	if manager == nil {
		return nil, fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	resetResp(key)
	cmdReq := &trident.RemoteExecRequest{ExecType: trident.ExecutionType_LIST_COMMAND.Enum()}
	manager.ExecCH <- cmdReq

	timeout := time.After(agentCommandTimeout)
	resp := &model.RemoteExecResp{}
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout(%vs) to get remote commands and linux namespace", agentCommandTimeout.Seconds())
		case <-manager.RemoteCMDDoneCH:
			resp.RemoteCommand = GetCommands(key)
			namespaceReq := &trident.RemoteExecRequest{ExecType: trident.ExecutionType_LIST_NAMESPACE.Enum()}
			manager.ExecCH <- namespaceReq
		case <-manager.LinuxNamespaceDoneCH:
			resp.LinuxNamespace = GetNamespaces(key)
		case <-manager.ExecDoneCH: // error occurred
			log.Errorf("get agent(key: %s) remote commands and linux namespace, error: %s", key, GetContent(key))
			return &model.RemoteExecResp{Content: GetContent(key)}, nil
		default:
			if len(GetCommands(key)) != 0 && len(GetNamespaces(key)) != 0 {
				log.Infof("len(commands)=%d, len(namespaces)=%d", len(GetCommands(key)), len(GetNamespaces(key)))
				return &model.RemoteExecResp{
					RemoteCommand:  GetCommands(key),
					LinuxNamespace: GetNamespaces(key),
				}, nil
			}
		}
	}
}

func RunAgentCMD(orgID, agentID int, req *trident.RemoteExecRequest) (string, error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return "", err
	}
	var agent *mysql.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return "", err
	}
	b, _ := json.Marshal(req)
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) run remote command, request: %s",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, string(b))
	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	if manager == nil {
		return "", fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	resetResp(key)
	manager.ExecCH <- req

	content := ""
	for {
		select {
		case <-time.After(agentCommandTimeout):
			return "", fmt.Errorf("timeout(%vs) to run agent command", agentCommandTimeout.Seconds())
		case <-manager.ExecDoneCH:
			content = manager.resp.Content
			log.Infof("command run content len: %d", len(content))
			return content, nil
		}
	}
}
