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
		log.Infof("[REMOTE_EXEC] agent(key: %s) cmd manager already exists, reusing existing manager", key)
		return manager.(*CMDManager)
	}
	log.Infof("[REMOTE_EXEC] new agent(key: %s) cmd manager, initial request_id: %d", key, requestID)
	newManager := &CMDManager{
		key:             key,
		RequestChan:     make(chan *grpcapi.RemoteExecRequest, 1),
		requestIDToResp: sync.Map{},
	}
	newManager.latestRequestID.Store(requestID)

	keyToAgentCMDManager.Store(key, newManager)
	log.Infof("[REMOTE_EXEC] agent(key: %s) cmd manager created successfully, ready to receive requests", key)
	return newManager
}

func RemoveAgentCMDManager(key string) {
	log.Infof("[REMOTE_EXEC] preparing to remove agent(key: %s) cmd manager", key)
	manager, ok := keyToAgentCMDManager.Load(key)
	if !ok {
		log.Warningf("[REMOTE_EXEC] agent(key: %s) cmd manager was removed before", key)
		return
	}
	m := manager.(*CMDManager)
	m.requestIDToResp.Range(func(k, v interface{}) bool {
		requestID := k.(uint64)
		cmdResp := v.(*CMDRespManager)
		errMessage := fmt.Sprintf("[REMOTE_EXEC] agent(key: %s, request id: %d) disconnected from the server", key, requestID)
		cmdResp.SetErrorMessage(errMessage)
		log.Warning(errMessage)
		cmdResp.close()
		return true
	})
	m.close()
	keyToAgentCMDManager.Delete(key)
	log.Infof("[REMOTE_EXEC] agent(key: %s) cmd manager is removed", key)
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

func (m *CMDManager) RemoveRespManager(requestID uint64) {
	m.requestIDToResp.Delete(requestID)
	log.Infof("[REMOTE_EXEC] response(key: %s, request id: %v) is removed", m.key, requestID)
}

func (m *CMDManager) GetRespManager(requestID uint64) *CMDRespManager {
	if resp, ok := m.requestIDToResp.Load(requestID); ok {
		return resp.(*CMDRespManager)
	}
	return &CMDRespManager{}
}
func (m *CMDManager) NewRespManager() (uint64, *CMDRespManager) {
	latestRequestID := m.latestRequestID.Add(1)
	resp := &CMDRespManager{
		requestID:                  latestRequestID,
		ResponseDoneChan:           make(chan struct{}, 1),
		GetRemoteCommandsDoneChan:  make(chan struct{}, 1),
		GetLinuxNamespacesDoneChan: make(chan struct{}, 1),
		IncrementalDataChan:        make(chan struct{}, 100), // 支持更高频率的增量通知
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
	IncrementalDataChan        chan struct{} // 用于增量数据通知的通道

	mutex          sync.Mutex
	ContentChunks  []string // 独立存储每次 Agent 响应的数据块，保持一一对应关系
	nextChunkIndex int      // 下一个待读取的 chunk 索引
	ErrorMessage   string
	RemoteExecResp
}

func (r *CMDRespManager) IsValid() bool {
	return r.requestID != 0
}

// AppendContent appends data to Content in a thread-safe way.
// 每次追加数据后会发送增量通知，支持流式处理
// 同时将数据作为独立块存储，保持与 Agent 响应的一一对应关系
func (r *CMDRespManager) AppendContent(data []byte) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// 保持向后兼容：继续追加到 Content 字符串
	r.Content += string(data)

	// 同时作为独立块存储，用于增量读取
	r.ContentChunks = append(r.ContentChunks, string(data))

	// 发送增量数据通知（非阻塞）
	select {
	case r.IncrementalDataChan <- struct{}{}:
		log.Debugf("[REMOTE_EXEC] 发送增量数据通知 (request_id: %d, chunk_index: %d, chunk_size: %d, total_chunks: %d, total_size: %d)",
			r.requestID, len(r.ContentChunks)-1, len(data), len(r.ContentChunks), len(r.Content))
	default:
		// 如果通道满了，跳过本次通知，避免阻塞
		log.Warningf("[REMOTE_EXEC] 增量数据通道已满，跳过通知 (request_id: %d, data_size: %d)",
			r.requestID, len(data))
	}
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

// GetContent returns Content in a thread-safe way.
func (r *CMDRespManager) GetContent() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.Content
}

// GetNewContent returns new content since the last call and updates the read position.
// 用于支持增量数据读取，返回自上次读取后的新内容
// 返回下一个未读取的数据块，保持与 Agent 响应的一一对应关系
func (r *CMDRespManager) GetNewContent(lastReadPos *int) string {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// 检查是否还有未读取的数据块
	if r.nextChunkIndex >= len(r.ContentChunks) {
		return ""
	}

	// 返回下一个数据块
	chunk := r.ContentChunks[r.nextChunkIndex]
	r.nextChunkIndex++

	// 更新 lastReadPos 以保持向后兼容
	*lastReadPos += len(chunk)

	return chunk
}

// GetErrorMessage returns ErrorMessage in a thread-safe way.
func (r *CMDRespManager) GetErrorMessage() string {
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
		close(r.IncrementalDataChan)
	})
}

func GetCMDAndNamespace(timeout, orgID, agentID int) (*RemoteExecResp, error) {
	log.Infof("[REMOTE_EXEC] current node ip(%s) get cmd and namespace", ctrlcommon.NodeIP)
	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	var agent *metadbmodel.VTap
	if err := dbInfo.Where("id = ?", agentID).Find(&agent).Error; err != nil {
		return nil, err
	}
	log.Infof("[REMOTE_EXEC] current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) get remote commands and linux namespaces",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, dbInfo.LogPrefixORGID)

	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := manager.NewRespManager()
	if !manager.IsValid() {
		return nil, fmt.Errorf("agent(key: %s, name: %s) cmd manager not found", key, agent.Name)
	}
	if !cmdResp.IsValid() {
		return nil, fmt.Errorf("agent(key: %s, name: %s) resp manager not found", key, agent.Name)
	}
	defer manager.RemoveRespManager(requestID)

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
			log.Errorf("[REMOTE_EXEC] get agent(key: %s) remote commands: %s, error: %s", key, cmdResp.GetContent(), cmdResp.GetErrorMessage(), dbInfo.LogPrefixORGID)
			errorMsg := cmdResp.GetErrorMessage()
			if errorMsg == "" {
				errorMsg = cmdResp.GetContent()
			}
			return nil, fmt.Errorf("[REMOTE_EXEC] failed to get agent(key: %s, name: %s) remote commands and linux namespaces, error: %s", key, agent.Name, errorMsg)
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
	log.Infof("[REMOTE_EXEC] current node ip(%s) agent(cur controller ip: %s, controller ip: %s, id: %d, name: %s) run remote command, request: %s",
		ctrlcommon.NodeIP, agent.CurControllerIP, agent.ControllerIP, agentID, agent.Name, string(b), dbInfo.LogPrefixORGID)
	key := agent.CtrlIP + "-" + agent.CtrlMac
	manager := GetAgentCMDManager(key)
	requestID, cmdResp := manager.NewRespManager()
	if !manager.IsValid() {
		return "", fmt.Errorf("agent(key: %s, name: %s) cmd manager not found", key, agent.Name)
	}
	if !cmdResp.IsValid() {
		return "", fmt.Errorf("agent(key: %s, name: %s) resp manager not found", key, agent.Name)
	}
	log.Infof("[REMOTE_EXEC] agent(key: %s) created response manager, request_id: %d", key, requestID)
	defer manager.RemoveRespManager(requestID)
	req.RequestId = &requestID
	log.Infof("[REMOTE_EXEC] agent(key: %s) sending request to RequestChan, request_id: %d", key, requestID)
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
			if msg := cmdResp.GetErrorMessage(); msg != "" {
				return cmdResp.GetContent(), fmt.Errorf("The deepflow-agent is unable to execute the `%s` command."+
					" Detailed error information is as follows:\n\n%s", CMD, msg)
			}
			content = cmdResp.GetContent()
			log.Infof("[REMOTE_EXEC] command run content len: %d", len(content), dbInfo.LogPrefixORGID)
			return content, nil
		}
	}
}
