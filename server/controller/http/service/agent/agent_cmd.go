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
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	grpcapi "github.com/deepflowio/deepflow/message/agent"
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

type RemoteExecReq struct {
	grpcapi.RemoteExecRequest

	OutputFormat   *grpcapi.OutputFormat `json:"output_format"` // 0: "TEXT", 1: "BINARY"
	OutputFilename string                `json:"output_filename"`
	CMD            string                `json:"cmd" binding:"required"`
}

type RemoteExecResp struct {
	Content        string                    `json:"content,omitempty"` // RUN_COMMAND
	ErrorMessage   string                    `json:"-"`
	RemoteCommand  []*grpcapi.RemoteCommand  `json:"remote_commands,omitempty"`  // LIST_COMMAND
	LinuxNamespace []*grpcapi.LinuxNamespace `json:"linux_namespaces,omitempty"` // LIST_NAMESPACE
}

var (
	agentCMDMutex   sync.RWMutex
	agentCMDManager = make(AgentCMDManager)
)

type AgentCMDManager map[string]*CMDManager

func LockAgentCMD() {
	agentCMDMutex.Lock()
}

func UnlockAgentCMD() {
	agentCMDMutex.Unlock()
}

func GetAgentCMDManager(key string) *CMDManager {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		return manager
	}
	return nil
}

func GetAgentCMDManagerWithoutLock(key string) *CMDManager {
	if manager, ok := agentCMDManager[key]; ok {
		return manager
	}
	return nil
}

func AddToCMDManagerIfNotExist(key string, requestID uint64) *CMDManager {
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	if _, ok := agentCMDManager[key]; ok {
		return agentCMDManager[key]
	}

	log.Infof("add agent(key:%s) to cmd manager", key)
	agentCMDManager[key] = &CMDManager{
		requestID:       requestID,
		ExecCH:          make(chan *grpcapi.RemoteExecRequest, 1),
		requestIDToResp: make(map[uint64]*CMDResp),
	}
	return agentCMDManager[key]
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
	log.Infof("preparing to remove all agent(key: %s) from cmd manager", key)
	agentCMDMutex.Lock()
	defer agentCMDMutex.Unlock()
	manager, ok := agentCMDManager[key]
	if !ok {
		log.Errorf("can not find agent command manager(key: %s)", key)
		return
	}

	for requestID, cmdResp := range manager.requestIDToResp {
		errMessage := fmt.Sprintf("agent(key: %s) disconnected from the server", key)
		AppendErrorMessage(key, requestID, &errMessage)
		log.Error(errMessage)
		close(cmdResp.ExecDoneCH)
		close(cmdResp.RemoteCMDDoneCH)
		close(cmdResp.LinuxNamespaceDoneCH)
	}
	close(manager.ExecCH)
	delete(agentCMDManager, key)
	log.Infof("delete agent(key: %s) in manager", key)
}

type CMDManager struct {
	requestID       uint64
	ExecCH          chan *grpcapi.RemoteExecRequest
	requestIDToResp map[uint64]*CMDResp
}

type CMDResp struct {
	ExecDoneCH           chan struct{}
	RemoteCMDDoneCH      chan struct{}
	LinuxNamespaceDoneCH chan struct{}

	data *RemoteExecResp
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
			data:                 &RemoteExecResp{},
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

func GetAgentCMDRespWithoutLock(key string, requestID uint64) *CMDResp {
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

func AppendCommands(key string, requestID uint64, data []*grpcapi.RemoteCommand) {
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.RemoteCommand = append(resp.data.RemoteCommand, data...)
		}
	}
}

func InitCommands(key string, requestID uint64, data []*grpcapi.RemoteCommand) {
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.RemoteCommand = data
		}
	}
}

func AppendNamespaces(key string, requestID uint64, data []*grpcapi.LinuxNamespace) {
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.LinuxNamespace = append(resp.data.LinuxNamespace, data...)
		}
	}
}

func InitNamespaces(key string, requestID uint64, data []*grpcapi.LinuxNamespace) {
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.LinuxNamespace = data
		}
	}
}

func AppendContent(key string, requestID uint64, data []byte) {
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			resp.data.Content += string(data)
		}
	}
}

func AppendErrorMessage(key string, requestID uint64, data *string) {
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

func GetCommands(key string, requestID uint64) []*grpcapi.RemoteCommand {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.RemoteCommand
		}
	}
	return nil
}

func GetCommandsWithoutLock(key string, requestID uint64) []*grpcapi.RemoteCommand {
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.RemoteCommand
		}
	}
	return nil
}

func GetNamespaces(key string, requestID uint64) []*grpcapi.LinuxNamespace {
	agentCMDMutex.RLock()
	defer agentCMDMutex.RUnlock()
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.LinuxNamespace
		}
	}
	return nil
}

func GetNamespacesWithoutLock(key string, requestID uint64) []*grpcapi.LinuxNamespace {
	if manager, ok := agentCMDManager[key]; ok {
		if resp, ok := manager.requestIDToResp[requestID]; ok {
			return resp.data.LinuxNamespace
		}
	}
	return nil
}

func GetCMDAndNamespace(timeout, orgID, agentID int) (*RemoteExecResp, error) {
	log.Infof("current node ip(%s) get cmd and namespace", ctrlcommon.NodeIP)
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	var agent *mysqlmodel.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return nil, err
	}
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) get remote commands and linux namespaces",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, dbInfo.LogPrefixORGID)

	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := NewAgentCMDResp(key)
	if manager == nil || cmdResp == nil {
		return nil, fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	defer RemoveAgentCMDResp(key, requestID)

	cmdReq := &grpcapi.RemoteExecRequest{
		RequestId: &requestID,
		ExecType:  grpcapi.ExecutionType_LIST_COMMAND.Enum(),
	}
	manager.ExecCH <- cmdReq

	cmdTimeout := time.After(time.Duration(timeout) * time.Second)
	resp := &RemoteExecResp{}
	for {
		select {
		case <-cmdTimeout:
			// RemoveAllFromCMDManager(key)
			return nil, fmt.Errorf("timeout(%vs) to get remote commands and linux namespace", timeout)
		case _, ok := <-cmdResp.RemoteCMDDoneCH:
			if !ok {
				return nil, fmt.Errorf("failed to get remote commands, agent(key: %s, name: %s) command manager is lost", key, agent.Name)
			}
			resp.RemoteCommand = GetCommands(key, requestID)
			namespaceReq := &grpcapi.RemoteExecRequest{RequestId: &requestID, ExecType: grpcapi.ExecutionType_LIST_NAMESPACE.Enum()}
			manager.ExecCH <- namespaceReq
		case _, ok := <-cmdResp.LinuxNamespaceDoneCH:
			if !ok {
				return nil, fmt.Errorf("failed to get linux namespaces, agent(key: %s, name: %s) command manager is lost", key, agent.Name)
			}
			resp.LinuxNamespace = GetNamespaces(key, requestID)
		case _, ok := <-cmdResp.ExecDoneCH: // error occurred
			if !ok {
				return nil, fmt.Errorf("failed to execute command, agent(key: %s, name: %s) command manager is lost", key, agent.Name)
			}
			if len(GetCommands(key, requestID)) != 0 {
				return &RemoteExecResp{RemoteCommand: GetCommands(key, requestID)}, nil
			}
			log.Errorf("get agent(key: %s) remote commands error: %s", key, GetContent(key, requestID), dbInfo.LogPrefixORGID)
			return nil, errors.New(key)
		default:
			if len(GetCommands(key, requestID)) != 0 && len(GetNamespaces(key, requestID)) != 0 {
				log.Infof("len(commands)=%d, len(namespaces)=%d",
					len(GetCommands(key, requestID)), len(GetNamespaces(key, requestID)), dbInfo.LogPrefixORGID)
				return &RemoteExecResp{
					RemoteCommand:  GetCommands(key, requestID),
					LinuxNamespace: GetNamespaces(key, requestID),
				}, nil
			}
		}
	}
}

func RunAgentCMD(timeout, orgID, agentID int, req *grpcapi.RemoteExecRequest, CMD string) (string, error) {
	serverLog := fmt.Sprintf("The deepflow-server is unable to execute the `%s` command."+
		" Detailed error information is as follows:\n\n", CMD)
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return "", fmt.Errorf("%s%s", serverLog, err.Error())
	}
	var agent *mysqlmodel.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return "", fmt.Errorf("%s%s", serverLog, err.Error())
	}
	b, _ := json.Marshal(req)
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) run remote command, request: %s",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, string(b), dbInfo.LogPrefixORGID)
	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := NewAgentCMDResp(key)
	if manager == nil || cmdResp == nil {
		return "", fmt.Errorf("agent(name: %s, key: %s) remote exec map not found", agent.Name, key)
	}
	defer RemoveAgentCMDResp(key, requestID)
	req.RequestId = &requestID
	manager.ExecCH <- req

	cmdTimeout := time.After(time.Duration(timeout) * time.Second)
	content := ""
	for {
		select {
		case <-cmdTimeout:
			err = fmt.Errorf("%stimeout(%vs) to run agent command", serverLog, timeout)
			log.Error(err, dbInfo.LogPrefixORGID)
			return "", err
		case _, ok := <-cmdResp.ExecDoneCH:
			if !ok {
				return "", fmt.Errorf("%sagent(key: %s, name: %s) command manager is lost", key, agent.Name)
			}
			if msg := GetErrormessage(key, requestID); msg != "" {
				return GetContent(key, requestID), fmt.Errorf("The deepflow-agent is unable to execute the `%s` command."+
					" Detailed error information is as follows:\n\n%s", CMD, msg)
			}
			content = GetContent(key, requestID)
			log.Infof("command run content len: %d", len(content), dbInfo.LogPrefixORGID)
			return content, nil
		}
	}
}
