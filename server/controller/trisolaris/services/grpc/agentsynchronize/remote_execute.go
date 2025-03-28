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

package agentsynchronize

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	api "github.com/deepflowio/deepflow/message/agent"
	service "github.com/deepflowio/deepflow/server/controller/http/service/agent"
)

const (
	CMD_INACTIVITY_TIMEOUT = 1 * time.Minute
)

func (e *AgentEvent) RemoteExecute(stream api.Synchronizer_RemoteExecuteServer) error {
	key := ""
	isFisrtRecv := false
	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		wg.Wait()
		service.RemoveAllFromCMDManager(key)
	}()

	var manager *service.CMDManager
	initDone := make(chan struct{})

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	errCH := make(chan error, 1)

	go func() {
		defer func() {
			log.Infof("agent(key: %s) remote exec stream receive goroutine done", key)
			wg.Done()
			if r := recover(); r != nil {
				buf := make([]byte, 2048)
				n := runtime.Stack(buf, false)
				errMsg := fmt.Sprintf("recovered in RemoteExecute: %s", buf[:n])
				log.Errorf(errMsg)
				errCH <- fmt.Errorf(errMsg)
			}
		}()

		inactivityTimer := time.NewTimer(CMD_INACTIVITY_TIMEOUT)
		defer inactivityTimer.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Infof("context done, agent(key: %s), context err: %v", key, ctx.Err())
				return
			case <-inactivityTimer.C:
				errMsg := fmt.Errorf("no message received for %vs, closing connection for agent(key: %s)",
					CMD_INACTIVITY_TIMEOUT.Seconds(), key)
				log.Error(errMsg)
				errCH <- errMsg
				return
			default:
				resp, err := stream.Recv()
				// Handle any errors that occur during stream reception
				// if server restart, an io.EOF error may be received
				if err == io.EOF {
					log.Errorf("agent(key: %s) command stream error: %v", key, err)
					errCH <- err
					return
				}
				// Attempt to stop the inactivity timer
				if !inactivityTimer.Stop() {
					// If the timer has already expired, drain the channel
					<-inactivityTimer.C
				}
				// Reset the inactivity timer to its original duration
				inactivityTimer.Reset(CMD_INACTIVITY_TIMEOUT)

				if resp == nil {
					continue
				}
				log.Debugf("agent command response: %s", resp.String())
				if resp.AgentId == nil {
					log.Warningf("recevie agent info from remote command is nil")
					continue
				}
				key = resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()
				if !isFisrtRecv {
					isFisrtRecv = true
					log.Infof("agent(key: %s) call RemoteExecute", key)
				}
				if manager == nil {
					log.Infof("agent(key: %s) remote exec map not found, add to cmd manager", key)
					manager = service.AddToCMDManagerIfNotExist(key, uint64(1))
					initDone <- struct{}{}
				}

				service.AgentCommandLock()
				manager = service.GetAgentCMDManagerWithoutLock(key)
				if manager == nil {
					log.Errorf("agent(key: %s) remote exec map not found", key)
					service.AgentCommandUnlock()
					continue
				}

				// heartbeat
				if resp.CommandResult == nil && resp.LinuxNamespaces == nil &&
					resp.Commands == nil && resp.Errmsg == nil {
					log.Infof("agent heart beat command response: %s", resp.String())
					manager.ExecCH <- &api.RemoteExecRequest{RequestId: proto.Uint64(0)}
					service.AgentCommandUnlock()
					continue
				}

				if err != nil {
					err := fmt.Errorf("agent(key: %s) command stream error: %v", key, err)
					log.Error(err)
					service.AgentCommandUnlock()
					continue
				}

				handleResponse(resp)
				service.AgentCommandUnlock()
			}
		}
	}()

	<-initDone
	log.Infof("agent(key: %s) init done", key)
	if manager == nil {
		err := fmt.Errorf("get agent(key: %s) remote exec manager nil", key)
		log.Error(err)
		return err
	}
	for {
		if manager == nil {
			err := fmt.Errorf("agent(key: %s) remote exec map not found", key)
			log.Error(err)
			return err
		}
		select {
		case <-ctx.Done():
			log.Infof("context done, agent(key: %s), context err: %v", key, ctx.Err())
			return ctx.Err()
		case err := <-errCH:
			log.Error(err)
			return err
		case req, ok := <-manager.ExecCH:
			if !ok {
				err := fmt.Errorf("agent(key: %s) exec channel is closed", key)
				log.Error(err)
				return err
			}
			b, _ := json.Marshal(req)
			log.Infof("agent(key: %s) request: %s", key, string(b))
			if err := stream.Send(req); err != nil {
				log.Errorf("send cmd to agent error: %s, req: %#v", err.Error(), req)
				return err
			}
		}
	}
}

func handleResponse(resp *api.RemoteExecResponse) {
	key := resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()
	if resp.RequestId == nil {
		log.Errorf("agent(key: %s) command resp request id not found", key, resp.RequestId)
		return
	}
	cmdResp := service.GetAgentCMDRespWithoutLock(key, *resp.RequestId)
	if cmdResp == nil {
		log.Errorf("agent(key: %s, request id: %v) remote exec map not found", key, resp.RequestId)
		return
	}

	b, _ := json.Marshal(resp)
	log.Infof("agent(key: %s) resp: %s", key, string(b))

	switch {
	case resp.Errmsg != nil:
		log.Errorf("agent(key: %s) run command error: %s",
			key, *resp.Errmsg)
		service.AppendErrorMessage(key, *resp.RequestId, resp.Errmsg)

		result := resp.CommandResult
		// get commands and linux namespace error
		if result == nil {
			cmdResp.ExecDoneCH <- struct{}{}
			return
		}
		if result.Content == nil {
			cmdResp.ExecDoneCH <- struct{}{}
			return
		}

		// run command error and handle content
		if result.Content != nil {
			service.AppendContent(key, *resp.RequestId, result.Content)
		}
		if result.Md5 != nil {
			cmdResp.ExecDoneCH <- struct{}{}
			return
		}
		return
	case len(resp.LinuxNamespaces) > 0:
		if len(service.GetNamespacesWithoutLock(key, *resp.RequestId)) > 0 {
			service.InitNamespaces(key, *resp.RequestId, resp.LinuxNamespaces)
		} else {
			service.AppendNamespaces(key, *resp.RequestId, resp.LinuxNamespaces)
		}
		cmdResp.LinuxNamespaceDoneCH <- struct{}{}
	case len(resp.Commands) > 0:
		if len(service.GetCommandsWithoutLock(key, *resp.RequestId)) > 0 {
			service.InitCommands(key, *resp.RequestId, resp.Commands)
		} else {
			service.AppendCommands(key, *resp.RequestId, resp.Commands)
		}
		cmdResp.RemoteCMDDoneCH <- struct{}{}
	default:
		result := resp.CommandResult
		if resp.CommandResult == nil {
			return
		}

		if result.Content != nil {
			service.AppendContent(key, *resp.RequestId, result.Content)
		}
		if result.Md5 != nil {
			cmdResp.ExecDoneCH <- struct{}{}
			return
		}
	}
}
