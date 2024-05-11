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
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/deepflowio/deepflow/message/trident"
	api "github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/http/service"
)

func (e *VTapEvent) RemoteExecute(stream api.Synchronizer_RemoteExecuteServer) error {
	key := ""
	ctx := stream.Context()

	for {
		// receive
		for {
			resp, err := stream.Recv()
			if resp == nil {
				break
			}
			if resp.AgentId == nil {
				log.Warningf("recevie agent info from remote command is nil")
				break
			}

			manager := service.GetAgentCMD()
			key = resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()
			if ok := service.IsAgentInit(key); !ok {
				manager = service.AddToManager(key)
				log.Infof("init agent(key:%s) resp", key)
			}

			if err != nil {
				if err == io.EOF {
					handleResponse(manager, resp)
					log.Infof("agent(key: %s) command exec get response finish", key)
					break
				}

				err := fmt.Errorf("agent(key: %s) command stream error: %v", key, err)
				log.Error(err)
				break
			}

			err = handleResponse(manager, resp)
			if err != nil {
				log.Error(err)
			}
			break
		}

		// send
		for {
			if key == "" {
				log.Infof("key is null when send request to agent")
				break
			}
			manager := service.GetAgentCMD()
			agentChan, ok := manager.GetAgentCommandChan(key)
			if !ok {
				err := fmt.Errorf("can not get agent command health check")
				log.Error(err)
				break
			}
			if len(agentChan.ExecCH) == 0 {
				break
			}

			select {
			case <-ctx.Done():
				log.Error(ctx.Err())
				manager.DeleteResp(key)
				return ctx.Err()
			case req := <-agentChan.ExecCH:
				b, _ := json.Marshal(req)
				log.Infof("weiqiang agent(key: %s) req: %s", key, string(b))
				if err := stream.Send(req); err != nil {
					log.Errorf("send cmd to agent error: %s, req: %#v", err.Error(), req)
					manager.DeleteResp(key)
					return err
				}
				log.Infof("weiqiang agent(key: %s) req finish: %s", key, string(b))
				break
			}
		}

	}
}

var ErrEndRecv = errors.New("end receive")

func handleResponse(manager *service.AgentCMD, resp *trident.RemoteExecResponse) error {
	key := resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()
	b, _ := json.Marshal(resp)
	log.Infof("weiqiang agent(key: %s) resp: %s", key, string(b))
	if ok := service.IsAgentInit(key); !ok {
		err := fmt.Errorf("agent(key: %s) is not init", key)
		log.Error(err)
		return err
	}
	agentChan, ok := manager.GetAgentCommandChan(key)
	if !ok {
		err := fmt.Errorf("agent(key: %s) command chan is not init", key)
		log.Error(err)
		return err
	}

	switch {
	case len(resp.LinuxNamespaces) > 0:
		if len(manager.GetNamespaces(key)) > 0 {
			manager.InitNamespaces(key, resp.LinuxNamespaces)
		} else {
			manager.AppendNamespaces(key, resp.LinuxNamespaces)
		}
		agentChan.LinuxNamespaceDoneCH <- struct{}{}
		return ErrEndRecv
	case len(resp.Commands) > 0:
		if len(manager.GetCommands(key)) > 0 {
			manager.InitCommands(key, resp.Commands)
		} else {
			manager.AppendCommands(key, resp.Commands)
		}
		agentChan.RemoteCMDDoneCH <- struct{}{}
		return ErrEndRecv
	default:
		log.Infof("weiqiang handle run command result")
		result := resp.CommandResult
		if resp.CommandResult == nil {
			return nil
		}
		b, _ := json.Marshal(resp.CommandResult)
		log.Infof("weiqiang agent(key: %s) resp command result: %s", key, string(b))

		if result.Errmsg != nil {
			log.Errorf("agent(key: %s) run command error: %s",
				key, *result.Errmsg)
			manager.AppendErr(key, result.Errmsg)
			agentChan.ExecDoneCH <- struct{}{}
			return ErrEndRecv
		}
		if result.Content != nil {
			manager.AppendContent(key, result.Content)
		}
		if result.Md5 != nil {
			agentChan.ExecDoneCH <- struct{}{}
			return ErrEndRecv
		}
	}
	return nil
}
