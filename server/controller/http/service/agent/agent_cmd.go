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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	grpcapi "github.com/deepflowio/deepflow/message/agent"
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type RemoteExecReq struct {
	grpcapi.RemoteExecRequest

	OutputFormat   *grpcapi.OutputFormat `json:"output_format"` // 0: "TEXT", 1: "BINARY"
	OutputFilename string                `json:"output_filename"`
	CMD            string                `json:"cmd" binding:"required"`
}

type RemoteExecResp struct {
	Content         string                    `json:"content,omitempty"`          // RUN_COMMAND
	RemoteCommands  []*grpcapi.RemoteCommand  `json:"remote_commands,omitempty"`  // LIST_COMMAND
	LinuxNamespaces []*grpcapi.LinuxNamespace `json:"linux_namespaces,omitempty"` // LIST_NAMESPACE
}

var keyToAgentCMDManager sync.Map // sync.Map[string]*CMDManager

func GetAgentCMDManager(key string) *CMDManager {
	if manager, ok := keyToAgentCMDManager.Load(key); ok {
		return manager.(*CMDManager)
	}
	return &CMDManager{}
}

func NewAgentCMDManagerIfNotExist(key string, requestID uint64) *CMDManager {
	manager, loaded := keyToAgentCMDManager.Load(key)
	if loaded {
		log.Infof("agent(key: %s) already exists, reusing existing manager", key)
		return manager.(*CMDManager)
	}
	log.Infof("new agent(key: %s)", key)
	newManager := &CMDManager{
		key:             key,
		RequestChan:     make(chan *grpcapi.RemoteExecRequest, 1),
		requestIDToResp: sync.Map{},
	}
	newManager.latestRequestID.Store(requestID)

	keyToAgentCMDManager.Store(key, newManager)
	return newManager
}

func RemoveAgentCMDManager(key string) {
	log.Infof("preparing to remove agent(key: %s)", key)
	manager, ok := keyToAgentCMDManager.Load(key)
	if !ok {
		log.Warningf("agent(key: %s) was removed before", key)
		return
	}
	m := manager.(*CMDManager)
	m.requestIDToResp.Range(func(k, v interface{}) bool {
		requestID := k.(uint64)
		cmdResp := v.(*CMDRespManager)
		errMessage := fmt.Sprintf("agent(key: %s, request id: %d) disconnected from the server", key, requestID)
		cmdResp.SetErrorMessage(errMessage)
		log.Warning(errMessage)
		cmdResp.close()
		return true
	})
	m.close()
	keyToAgentCMDManager.Delete(key)
	log.Infof("agent(key: %s) is removed", key)
}

type CMDManager struct {
	key string

	RequestChan     chan *grpcapi.RemoteExecRequest
	latestRequestID atomic.Uint64
	requestIDToResp sync.Map // sync.Map[uint64]*CMDResp
}

func (m *CMDManager) IsValid() bool {
	return m.key != ""
}

func (m *CMDManager) removeRespManager(requestID uint64) {
	m.requestIDToResp.Delete(requestID)
	log.Infof("response(key: %s, request id: %v) is removed", m.key, requestID)
}

func (m *CMDManager) GetRespManager(requestID uint64) *CMDRespManager {
	if resp, ok := m.requestIDToResp.Load(requestID); ok {
		return resp.(*CMDRespManager)
	}
	return &CMDRespManager{}
}
func (m *CMDManager) newRespManager() (uint64, *CMDRespManager) {
	latestRequestID := m.latestRequestID.Add(1)
	resp := &CMDRespManager{
		requestID:                  latestRequestID,
		ResponseDoneChan:           make(chan struct{}, 1),
		GetRemoteCommandsDoneChan:  make(chan struct{}, 1),
		GetLinuxNamespacesDoneChan: make(chan struct{}, 1),
		RemoteExecResp:             RemoteExecResp{},
	}
	m.requestIDToResp.Store(latestRequestID, resp)
	return latestRequestID, resp
}

func (m *CMDManager) close() {
	close(m.RequestChan)
}

type CMDRespManager struct {
	requestID uint64

	closeOnce                  sync.Once
	ResponseDoneChan           chan struct{}
	GetRemoteCommandsDoneChan  chan struct{}
	GetLinuxNamespacesDoneChan chan struct{}

	mutex        sync.Mutex
	ErrorMessage string
	RemoteExecResp
}

func (r *CMDRespManager) IsValid() bool {
	return r.requestID != 0
}

// AppendContent appends data to Content in a thread-safe way.
func (r *CMDRespManager) AppendContent(data []byte) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.Content += string(data)
}

// SetErrorMessage sets ErrorMessage in a thread-safe way.
func (r *CMDRespManager) SetErrorMessage(msg string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.ErrorMessage = msg
}

// SetRemoteCommands sets RemoteCommands in a thread-safe way.
func (r *CMDRespManager) SetRemoteCommands(cmds []*grpcapi.RemoteCommand) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.RemoteCommands = cmds
}

// SetLinuxNamespaces sets LinuxNamespaces in a thread-safe way.
func (r *CMDRespManager) SetLinuxNamespaces(ns []*grpcapi.LinuxNamespace) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.LinuxNamespaces = ns
}

// getContent returns Content in a thread-safe way.
func (r *CMDRespManager) getContent() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.Content
}

// getErrorMessage returns ErrorMessage in a thread-safe way.
func (r *CMDRespManager) getErrorMessage() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.ErrorMessage
}

// getRemoteCommands returns RemoteCommands in a thread-safe way.
func (r *CMDRespManager) getRemoteCommands() []*grpcapi.RemoteCommand {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.RemoteCommands
}

// getLinuxNamespaces returns LinuxNamespaces in a thread-safe way.
func (r *CMDRespManager) getLinuxNamespaces() []*grpcapi.LinuxNamespace {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.LinuxNamespaces
}

func (r *CMDRespManager) close() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Use sync.Once to prevent double-close
	r.closeOnce.Do(func() {
		close(r.ResponseDoneChan)
		close(r.GetRemoteCommandsDoneChan)
		close(r.GetLinuxNamespacesDoneChan)
	})
}

func GetCMDAndNamespace(timeout, orgID, agentID int) (*RemoteExecResp, error) {
	log.Infof("current node ip(%s) get cmd and namespace", ctrlcommon.NodeIP)
	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	var agent *metadbmodel.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return nil, err
	}
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) get remote commands and linux namespaces",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, dbInfo.LogPrefixORGID)

	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := manager.newRespManager()
	if !manager.IsValid() {
		return nil, fmt.Errorf("agent(key: %s, name: %s) cmd manager not found", key, agent.Name)
	}
	if !cmdResp.IsValid() {
		return nil, fmt.Errorf("agent(key: %s, name: %s) resp manager not found", key, agent.Name)
	}
	defer manager.removeRespManager(requestID)

	listCmdReq := &grpcapi.RemoteExecRequest{
		RequestId: &requestID,
		ExecType:  grpcapi.ExecutionType_LIST_COMMAND.Enum(),
	}
	manager.RequestChan <- listCmdReq

	cmdTimeout := time.After(time.Duration(timeout) * time.Second)
	resp := &RemoteExecResp{}

	var commandsReceived, namespacesReceived bool
	for !commandsReceived || !namespacesReceived {
		select {
		case <-cmdTimeout:
			return nil, fmt.Errorf("timeout(%vs) to get agent(key: %s, name: %s) remote commands and linux namespace", timeout, key, agent.Name)
		case _, ok := <-cmdResp.GetRemoteCommandsDoneChan:
			if !ok {
				return nil, fmt.Errorf("failed to get remote commands, agent(key: %s, name: %s) command manager is lost", key, agent.Name)
			}
			resp.RemoteCommands = cmdResp.getRemoteCommands()
			commandsReceived = true

			// Only send namespace request after commands are received
			if !namespacesReceived {
				listNamespaceReq := &grpcapi.RemoteExecRequest{
					RequestId: &requestID,
					ExecType:  grpcapi.ExecutionType_LIST_NAMESPACE.Enum(),
				}
				manager.RequestChan <- listNamespaceReq
			}
		case _, ok := <-cmdResp.GetLinuxNamespacesDoneChan:
			if !ok {
				return nil, fmt.Errorf("failed to get linux namespaces, agent(key: %s, name: %s) command manager is lost", key, agent.Name)
			}
			resp.LinuxNamespaces = cmdResp.getLinuxNamespaces()
			namespacesReceived = true

		case _, ok := <-cmdResp.ResponseDoneChan: // error occurred
			if !ok {
				return nil, fmt.Errorf("failed to execute command, agent(key: %s, name: %s) command manager is lost", key, agent.Name)
			}
			if commandsReceived || len(cmdResp.getRemoteCommands()) != 0 {
				return &RemoteExecResp{RemoteCommands: cmdResp.getRemoteCommands()}, nil
			}
			log.Errorf("get agent(key: %s) remote commands: %s, error: %s", key, cmdResp.getContent(), cmdResp.getErrorMessage(), dbInfo.LogPrefixORGID)
			errorMsg := cmdResp.getErrorMessage()
			if errorMsg == "" {
				errorMsg = cmdResp.getContent()
			}
			return nil, fmt.Errorf("failed to get agent(key: %s, name: %s) remote commands and linux namespaces, error: %s", key, agent.Name, errorMsg)
		}
	}
	return &RemoteExecResp{
		RemoteCommands:  resp.RemoteCommands,
		LinuxNamespaces: resp.LinuxNamespaces,
	}, nil
}

func RunAgentCMD(timeout, orgID, agentID int, req *grpcapi.RemoteExecRequest, CMD string) (string, error) {
	serverLog := fmt.Sprintf("The deepflow-server is unable to execute the `%s` command."+
		" Detailed error information is as follows:\n\n", CMD)
	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return "", fmt.Errorf("%s%s", serverLog, err.Error())
	}
	var agent *metadbmodel.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return "", fmt.Errorf("%s%s", serverLog, err.Error())
	}
	b, _ := json.Marshal(req)
	log.Infof("current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) run remote command, request: %s",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, string(b), dbInfo.LogPrefixORGID)
	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := manager.newRespManager()
	if !manager.IsValid() {
		return "", fmt.Errorf("agent(key: %s, name: %s) cmd manager not found", key, agent.Name)
	}
	if !cmdResp.IsValid() {
		return "", fmt.Errorf("agent(key: %s, name: %s) resp manager not found", key, agent.Name)
	}
	defer manager.removeRespManager(requestID)
	req.RequestId = &requestID
	manager.RequestChan <- req

	cmdTimeout := time.After(time.Duration(timeout) * time.Second)
	content := ""
	for {
		select {
		case <-cmdTimeout:
			err = fmt.Errorf("%stimeout(%vs) to run agent command", serverLog, timeout)
			log.Error(err, dbInfo.LogPrefixORGID)
			return "", err
		case _, ok := <-cmdResp.ResponseDoneChan:
			if !ok {
				return "", fmt.Errorf("%sagent(key: %s, name: %s) command manager is lost", serverLog, key, agent.Name)
			}
			if msg := cmdResp.getErrorMessage(); msg != "" {
				return cmdResp.getContent(), fmt.Errorf("The deepflow-agent is unable to execute the `%s` command."+
					" Detailed error information is as follows:\n\n%s", CMD, msg)
			}
			content = cmdResp.getContent()
			log.Infof("command run content len: %d", len(content), dbInfo.LogPrefixORGID)
			return content, nil
		}
	}
}
