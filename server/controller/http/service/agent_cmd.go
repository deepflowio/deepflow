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
	AgentRemoteExecMap  = make(map[string]*CMDManager)
	agentCommandTimeout = time.Second * 5
)

func AddSteamToManager(key string) *CMDManager {
	m := initCMDManager()
	AgentRemoteExecMap[key] = m
	return m
}

func initCMDManager() *CMDManager {
	m := &CMDManager{
		ExecCH:               make(chan *trident.RemoteExecRequest, 1),
		ExecDoneCH:           make(chan struct{}, 1),
		RemoteCMDDoneCH:      make(chan struct{}, 1),
		LinuxNamespaceDoneCH: make(chan struct{}, 1),

		resp: &model.RemoteExecResp{},
	}
	return m
}

type CMDManager struct {
	mu sync.RWMutex

	ExecCH               chan *trident.RemoteExecRequest
	ExecDoneCH           chan struct{}
	RemoteCMDDoneCH      chan struct{}
	LinuxNamespaceDoneCH chan struct{}

	resp *model.RemoteExecResp

	stream trident.Synchronizer_RemoteExecuteServer
}

func (m *CMDManager) ResetResp() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resp = &model.RemoteExecResp{}

}

func (m *CMDManager) AppendCommands(data []*trident.RemoteCommand) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resp.RemoteCommand = append(m.resp.RemoteCommand, data...)
}

func (m *CMDManager) InitCommands(data []*trident.RemoteCommand) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resp.RemoteCommand = data
}

func (m *CMDManager) AppendNamespaces(data []*trident.LinuxNamespace) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resp.LinuxNamespace = append(m.resp.LinuxNamespace, data...)
}

func (m *CMDManager) InitNamespaces(data []*trident.LinuxNamespace) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resp.LinuxNamespace = data
}

func (m *CMDManager) AppendContent(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resp.Content += string(data)
}

func (m *CMDManager) AppendErr(data *string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resp.Content += *data
}

func (m *CMDManager) GetCommands() []*trident.RemoteCommand {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := m.resp.RemoteCommand
	return result
}

func (m *CMDManager) GetNamespaces() []*trident.LinuxNamespace {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := m.resp.LinuxNamespace
	return result
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
	manager, ok := AgentRemoteExecMap[key]
	if !ok {
		return nil, fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	manager.ResetResp()
	cmdReq := &trident.RemoteExecRequest{ExecType: trident.ExecutionType_LIST_COMMAND.Enum()}
	manager.ExecCH <- cmdReq

	resp := &model.RemoteExecResp{}
	for {
		select {
		case <-time.After(agentCommandTimeout):
			return nil, fmt.Errorf("timeout(%vs) to get remote commands and linux namespace", agentCommandTimeout.Seconds())
		case <-manager.RemoteCMDDoneCH:
			resp.RemoteCommand = manager.GetCommands()
			namespaceReq := &trident.RemoteExecRequest{ExecType: trident.ExecutionType_LIST_NAMESPACE.Enum()}
			manager.ExecCH <- namespaceReq
		case <-manager.LinuxNamespaceDoneCH:
			resp.LinuxNamespace = manager.GetNamespaces()
		default:
			if len(manager.GetCommands()) != 0 && len(manager.GetNamespaces()) != 0 {
				log.Infof("len(commands)=%d, len(namespaces)=%d", len(manager.GetCommands()), len(manager.GetNamespaces()))
				return &model.RemoteExecResp{
					RemoteCommand:  manager.GetCommands(),
					LinuxNamespace: manager.GetNamespaces(),
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
	manager, ok := AgentRemoteExecMap[key]
	if !ok {
		return "", fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	manager.ResetResp()
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
