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
	agentCommandTimeout = time.Second * 5

	cmd = &AgentCMD{
		channels:  &AgentChan{keyToChan: make(map[string]*AgentCommandChan)},
		keyToResp: make(map[string]*model.RemoteExecResp),
	}
)

type AgentCMD struct {
	mu        sync.RWMutex
	channels  *AgentChan // only init once
	keyToResp map[string]*model.RemoteExecResp
}

type AgentChan struct {
	keyToChan map[string]*AgentCommandChan
}

type AgentCommandChan struct {
	ExecCH               chan *trident.RemoteExecRequest
	ExecDoneCH           chan struct{}
	RemoteCMDDoneCH      chan struct{}
	LinuxNamespaceDoneCH chan struct{}
}

func GetAgentCMD() *AgentCMD {
	return cmd
}

func IsAgentInit(key string) bool {
	cmd.mu.Lock()
	defer cmd.mu.Unlock()
	_, ok1 := cmd.keyToResp[key]
	_, ok2 := cmd.keyToResp[key]
	return ok1 && ok2
}

func IsAgentChanInit(key string) bool {
	cmd.mu.Lock()
	defer cmd.mu.Unlock()
	_, ok := cmd.channels.keyToChan[key]
	return ok
}

func IsAgentHealth(key string) bool {
	cmd.mu.Lock()
	defer cmd.mu.Unlock()
	_, ok := cmd.keyToResp[key]
	return ok
}

func AddToManager(key string) *AgentCMD {
	cmd.mu.Lock()
	defer cmd.mu.Unlock()
	if _, ok := cmd.channels.keyToChan[key]; !ok {
		cmd.channels.keyToChan[key] = &AgentCommandChan{
			ExecCH:               make(chan *trident.RemoteExecRequest, 1),
			ExecDoneCH:           make(chan struct{}, 1),
			RemoteCMDDoneCH:      make(chan struct{}, 1),
			LinuxNamespaceDoneCH: make(chan struct{}, 1),
		}
	}
	if _, ok := cmd.keyToResp[key]; !ok {
		cmd.keyToResp[key] = &model.RemoteExecResp{}
	}
	return cmd
}

func (a *AgentCMD) DeleteResp(key string) {
	cmd.mu.Lock()
	defer cmd.mu.Unlock()
	delete(a.keyToResp, key)
}

func (a *AgentCMD) GetAgentCommandChan(key string) (*AgentCommandChan, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.channels.keyToChan[key]
	return v, ok
}

func (a *AgentCMD) ResetResp(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.keyToResp[key]; ok {
		a.keyToResp[key] = &model.RemoteExecResp{}
	}
}

func (a *AgentCMD) AppendCommands(key string, data []*trident.RemoteCommand) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		resp.RemoteCommand = append(resp.RemoteCommand, data...)
	}
}

func (a *AgentCMD) InitCommands(key string, data []*trident.RemoteCommand) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		resp.RemoteCommand = data
	}
}

func (a *AgentCMD) AppendNamespaces(key string, data []*trident.LinuxNamespace) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		resp.LinuxNamespace = append(resp.LinuxNamespace, data...)
	}
}

func (a *AgentCMD) InitNamespaces(key string, data []*trident.LinuxNamespace) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		resp.LinuxNamespace = data
	}
}

func (a *AgentCMD) AppendContent(key string, data []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		resp.Content += string(data)
	}
}

func (a *AgentCMD) AppendErr(key string, data *string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		resp.Content += *data
	}
}

func (a *AgentCMD) GetCommands(key string) []*trident.RemoteCommand {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		return resp.RemoteCommand
	}
	return nil
}

func (a *AgentCMD) GetNamespaces(key string) []*trident.LinuxNamespace {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		return resp.LinuxNamespace
	}
	return nil
}

func (a *AgentCMD) GetContent(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if resp, ok := a.keyToResp[key]; ok {
		return resp.Content
	}
	return ""
}

func GetCMDAndNamespace(orgID, agentID int) (*model.RemoteExecResp, error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	var agent *mysql.VTap
	// TODO(weiqiang): add team filter
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return nil, err
	}
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) get remote commands and linux namespaces",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name)

	key := agent.CtrlIP + "-" + agent.CtrlMac
	if ok := IsAgentInit(key); !ok {
		err := fmt.Errorf("agent(key: %s) is not init", key)
		log.Error(err)
		return nil, err
	}
	manager, ok := cmd.GetAgentCommandChan(key)
	if !ok {
		err := fmt.Errorf("can not get agent command health check")
		log.Error(err)
		return nil, err
	}

	cmd.ResetResp(key)
	cmdReq := &trident.RemoteExecRequest{ExecType: trident.ExecutionType_LIST_COMMAND.Enum()}
	manager.ExecCH <- cmdReq

	resp := &model.RemoteExecResp{}
	for {
		select {
		case <-time.After(agentCommandTimeout):
			return nil, fmt.Errorf("timeout(%vs) to get remote commands and linux namespace", agentCommandTimeout.Seconds())
		case <-manager.RemoteCMDDoneCH:
			resp.RemoteCommand = cmd.GetCommands(key)
			namespaceReq := &trident.RemoteExecRequest{ExecType: trident.ExecutionType_LIST_NAMESPACE.Enum()}
			manager.ExecCH <- namespaceReq
		case <-manager.LinuxNamespaceDoneCH:
			resp.LinuxNamespace = cmd.GetNamespaces(key)
		default:
			if len(cmd.GetCommands(key)) != 0 && len(cmd.GetNamespaces(key)) != 0 {
				log.Infof("weiqiang len(cmd.GetCommands(key))=%d, len(cmd.GetNamespaces(key))=%d",
					len(cmd.GetCommands(key)), len(cmd.GetNamespaces(key)))
				b, _ := json.Marshal(resp)

				log.Infof("weiqiang resp: %s", string(b))
				return &model.RemoteExecResp{
					RemoteCommand:  cmd.GetCommands(key),
					LinuxNamespace: cmd.GetNamespaces(key),
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
	// TODO(weiqiang): add team filter
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return "", err
	}
	b, _ := json.Marshal(req)
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) run remote command, request: %s",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, string(b))
	key := agent.CtrlIP + "-" + agent.CtrlMac
	if ok := IsAgentInit(key); !ok {
		err := fmt.Errorf("agent(key: %s) is not init", key)
		log.Error(err)
		return "", err
	}
	manager, ok := cmd.GetAgentCommandChan(key)
	if !ok {
		err := fmt.Errorf("can not get agent command health check")
		log.Error(err)
		return "", err
	}
	cmd.ResetResp(key)
	manager.ExecCH <- req

	content := ""
	for {
		select {
		case <-time.After(agentCommandTimeout):
			return "", fmt.Errorf("timeout(%vs) to run agent command", agentCommandTimeout.Seconds())
		case <-manager.ExecDoneCH:
			content = cmd.GetContent(key)
			log.Infof("weiqiang command run content: %s", content)
			return content, nil
		}
	}
}
