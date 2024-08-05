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

package synchronize

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/deepflowio/deepflow/message/trident"
	api "github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"google.golang.org/protobuf/proto"
)

func (e *VTapEvent) RemoteExecute(stream api.Synchronizer_RemoteExecuteServer) error {
	key := ""
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

	go func() {
		defer func() {
			wg.Done()
			if r := recover(); r != nil {
				buf := make([]byte, 2048)
				n := runtime.Stack(buf, false)
				log.Errorf("recovered in RemoteExecute: %s", buf[:n])
			}
		}()

		<-initDone
		if manager == nil {
			err := fmt.Errorf("get agent(key: %s) remote exec manager nil", key)
			log.Error(err)
			return
		}

		for {
			select {
			case <-ctx.Done():
				log.Infof("context done, agent(key: %s)", key)
				return
			case req, ok := <-manager.ExecCH:
				if !ok {
					err := fmt.Errorf("agent(key: %s) exec channel is closed", key)
					log.Error(err)
					return
				}
				b, _ := json.Marshal(req)
				log.Infof("agent(key: %s) request: %s", key, string(b))
				if err := stream.Send(req); err != nil {
					log.Errorf("send cmd to agent error: %s, req: %#v", err.Error(), req)
					return
				}
			}
		}

	}()

	for {
		select {
		case <-ctx.Done():
			log.Infof("context done, agent(key: %s)", key)
			return nil
		default:
			resp, err := stream.Recv()
			if resp == nil {
				continue
			}
			log.Infof("agent command response: %s", resp.String())
			if resp.AgentId == nil {
				log.Warningf("recevie agent info from remote command is nil")
				continue
			}
			key = resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()
			if manager = service.GetAgentCMDManager(key); manager == nil {
				service.AddToCMDManager(key, uint64(1))
				log.Infof("add agent(key:%s) to cmd manager", key)
				initDone <- struct{}{}
			}
			manager = service.GetAgentCMDManager(key)
			if manager == nil {
				log.Errorf("agent(key: %s) remote exec map not found", key)
				continue
			}

			// time.Sleep(time.Minute)

			// heartbeat
			if resp.CommandResult == nil && resp.LinuxNamespaces == nil &&
				resp.Commands == nil && resp.Errmsg == nil {
				log.Infof("agent heart beat command response: %s", resp.String())
				manager.ExecCH <- &api.RemoteExecRequest{RequestId: proto.Uint64(0)}
				continue
			}

			if err != nil {
				if err == io.EOF {
					handleResponse(resp)
					log.Infof("agent(key: %s) command exec get response finish", key)
					continue
				}

				err := fmt.Errorf("agent(key: %s) command stream error: %v", key, err)
				log.Error(err)
				continue
			}

			handleResponse(resp)
		}
	}
}

func handleResponse(resp *trident.RemoteExecResponse) {
	key := resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()
	if resp.RequestId == nil {
		log.Errorf("agent(key: %s) command resp request id not found", key, resp.RequestId)
		return
	}
	cmdResp := service.GetAgentCMDResp(key, *resp.RequestId)
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
		if len(service.GetNamespaces(key, *resp.RequestId)) > 0 {
			service.InitNamespaces(key, *resp.RequestId, resp.LinuxNamespaces)
		} else {
			service.AppendNamespaces(key, *resp.RequestId, resp.LinuxNamespaces)
		}
		cmdResp.LinuxNamespaceDoneCH <- struct{}{}
	case len(resp.Commands) > 0:
		if len(service.GetCommands(key, *resp.RequestId)) > 0 {
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
