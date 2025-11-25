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
	agentInactivityTimeout         = 1 * time.Minute
	reqeustIDOfResponseToHeartbeat = 0
)

func newRemoteExecContext(streamCtx context.Context) *remoteExecContext {
	streamCtx, cancel := context.WithCancel(streamCtx)
	return &remoteExecContext{
		streamCtx:           streamCtx,
		streamCancel:        cancel,
		streamHandleErrChan: make(chan error, 1),
		cmdMngInitDoneChan:  make(chan struct{}),
	}
}

type remoteExecContext struct {
	streamCtx    context.Context // stream context
	streamCancel context.CancelFunc

	heartbeatCount uint32 // used to sample the agent's heartbeats

	wg                  sync.WaitGroup
	streamHandleErrChan chan error    // channel to handle errors
	cmdMngInitDoneChan  chan struct{} // channel to signal initialization done

	// the following fields are initialized after the first message is received
	isFirstRecv bool   // whether the first message has been received
	key         string // agent key, format: ip-mac
	cmdMng      *service.CMDManager
}

func (e *RemoteExecute) RemoteExecute(stream api.Synchronizer_RemoteExecuteServer) error {
	ctx := newRemoteExecContext(stream.Context())
	ctx.wg.Add(1)
	defer func() {
		ctx.wg.Wait()
		close(ctx.streamHandleErrChan)
		close(ctx.cmdMngInitDoneChan)
		service.RemoveAgentCMDManager(ctx.key)
	}()

	defer ctx.streamCancel()

	go e.receiveAndHandle(ctx, stream)

	<-ctx.cmdMngInitDoneChan
	log.Infof("agent(key: %s) cmd manager init done", ctx.key)

	return e.waitAndSend(ctx, stream)
}

func (e *RemoteExecute) receiveAndHandle(
	ctx *remoteExecContext,
	stream api.Synchronizer_RemoteExecuteServer,
) {
	defer func() {
		if r := recover(); r != nil {
			e.handlePanic(ctx)
		}
		log.Infof("agent(key: %s) remote exec stream receive goroutine done", ctx.key)
		ctx.wg.Done()
	}()

	agentInactivityTimer := time.NewTimer(agentInactivityTimeout)
	defer agentInactivityTimer.Stop()

	for {
		select {
		case <-ctx.streamCtx.Done():
			log.Infof("agent(key: %s) stream context done, err: %v", ctx.key, ctx.streamCtx.Err())
			return
		case <-agentInactivityTimer.C:
			e.handleAgentInactivityTimeout(ctx)
			return
		default:
			resp, err := stream.Recv()
			// Handle any errors that occur during stream reception
			// if server restart, an io.EOF error may be received
			if err == io.EOF {
				e.handleStreamEOF(ctx, err)
				return
			}

			e.resetTimer(ctx, agentInactivityTimer)

			if resp == nil {
				log.Infof("agent received null response: %s", resp.String())
				return
			}
			if resp.AgentId == nil {
				log.Warningf("agent received null agent id: %s", resp.String())
				return
			}

			e.initCtx(ctx, resp)

			if !ctx.cmdMng.IsValid() {
				log.Errorf("agent(key: %s) cmd manager not found", ctx.key)
				continue
			}

			if e.isHeartbeat(resp) {
				e.logHeartbeat(ctx, resp)
				// response to agent heartbeat
				ctx.cmdMng.RequestChan <- &api.RemoteExecRequest{RequestId: proto.Uint64(reqeustIDOfResponseToHeartbeat)}
				continue
			}

			if err != nil {
				log.Errorf("agent(key: %s) received strem error: %s", ctx.key, err.Error())
				continue
			}

			e.handleResponse(ctx, resp)
		}
	}
}

func (e *RemoteExecute) initCtx(ctx *remoteExecContext, resp *api.RemoteExecResponse) {
	log.Debugf("agent command response: %s", resp.String())
	ctx.key = resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()

	if !ctx.isFirstRecv {
		ctx.isFirstRecv = true
		log.Infof("agent(key: %s) called me for the first time", ctx.key)
	}

	if ctx.cmdMng == nil {
		log.Infof("agent(key: %s) cmd manager not found, new one manager", ctx.key)
		ctx.cmdMng = service.NewAgentCMDManagerIfNotExist(ctx.key, uint64(1))
		ctx.cmdMngInitDoneChan <- struct{}{}
	} else {
		ctx.cmdMng = service.GetAgentCMDManager(ctx.key)
	}
}

func (e *RemoteExecute) handleResponse(ctx *remoteExecContext, resp *api.RemoteExecResponse) {
	if resp.RequestId == nil {
		log.Errorf("agent(key: %s) responsed null request id", ctx.key)
		return
	}

	cmdRespMng := ctx.cmdMng.GetRespManager(*resp.RequestId)
	if !cmdRespMng.IsValid() {
		log.Errorf("agent(key: %s, request id: %v) response manager not found", ctx.key, resp.RequestId)
		return
	}

	e.logResponse(resp, ctx.key)

	switch {
	case resp.Errmsg != nil:
		log.Errorf("agent(key: %s, request id: %v) run command error: %s", ctx.key, *resp.RequestId, *resp.Errmsg)
		cmdRespMng.SetErrorMessage(*resp.Errmsg)

		result := resp.CommandResult
		if result == nil || result.Content == nil {
			cmdRespMng.ResponseDoneChan <- struct{}{}
			return
		}
		cmdRespMng.AppendContent(result.Content)

		// check if response is completed
		if result.Md5 != nil {
			cmdRespMng.ResponseDoneChan <- struct{}{}
			return
		}
		return
	case len(resp.LinuxNamespaces) > 0:
		cmdRespMng.SetLinuxNamespaces(resp.LinuxNamespaces)
		cmdRespMng.GetLinuxNamespacesDoneChan <- struct{}{}
		return
	case len(resp.Commands) > 0:
		cmdRespMng.SetRemoteCommands(resp.Commands)
		cmdRespMng.GetRemoteCommandsDoneChan <- struct{}{}
		return
	default:
		log.Infof("agent(key: %s, request id: %v) responsed default", ctx.key, *resp.RequestId)
		result := resp.CommandResult
		if result == nil {
			return
		}
		if result.Content != nil {
			cmdRespMng.AppendContent(result.Content)
		}
		if result.Md5 != nil {
			cmdRespMng.ResponseDoneChan <- struct{}{}
			return
		}
	}
}

func (e *RemoteExecute) waitAndSend(
	ctx *remoteExecContext,
	stream api.Synchronizer_RemoteExecuteServer,
) error {
	for {
		if !ctx.cmdMng.IsValid() {
			err := fmt.Errorf("agent(key: %s) cmd manager is invalid", ctx.key)
			log.Error(err)
			return err
		}

		select {
		case <-ctx.streamCtx.Done():
			log.Infof("agent(key: %s) stream context done, err: %v", ctx.key, ctx.streamCtx.Err())
			return ctx.streamCtx.Err()
		case err := <-ctx.streamHandleErrChan:
			log.Error(err)
			return err
		case req, ok := <-ctx.cmdMng.RequestChan:
			if !ok {
				err := fmt.Errorf("agent(key: %s) cmd manager request channel has been closed", ctx.key)
				log.Error(err)
				return err
			}
			if err := e.sendRequest(ctx, stream, req); err != nil {
				return err
			}
		}
	}
}

func (e *RemoteExecute) handlePanic(ctx *remoteExecContext) {
	buf := make([]byte, 2048)
	n := runtime.Stack(buf, false)
	err := fmt.Errorf("agent(key: %s) recovered in RemoteExecute: %s", ctx.key, buf[:n])
	log.Error(err.Error())
	// Send error to errChan in a non-blocking way to prevent deadlock
	select {
	case ctx.streamHandleErrChan <- err:
	default:
		log.Errorf("agent(key: %s) error channel is full, could not send panic error", ctx.key)
	}
}

func (e *RemoteExecute) handleAgentInactivityTimeout(ctx *remoteExecContext) {
	err := fmt.Errorf("no message received for %vs, closing connection for agent(key: %s)",
		agentInactivityTimeout.Seconds(), ctx.key)
	log.Error(err.Error())
	// Send error to errChan in a non-blocking way to prevent deadlock
	select {
	case ctx.streamHandleErrChan <- err:
	default:
		log.Errorf("agent(key: %s) error channel is full, could not send timeout error", ctx.key)
	}
}

func (e *RemoteExecute) handleStreamEOF(ctx *remoteExecContext, err error) {
	log.Errorf("agent(key: %s) command stream error: %v", ctx.key, err)
	// Send error to errChan in a non-blocking way to prevent deadlock
	select {
	case ctx.streamHandleErrChan <- err:
	default:
		log.Warningf("agent(key: %s) error channel is full, dropping error: %v", ctx.key, err)
	}
}

// resetTimer attempts to stop the inactivity timer and reset it to its original duration.
// If the timer has already expired, it drains the channel to prevent blocking.
func (e *RemoteExecute) resetTimer(ctx *remoteExecContext, timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
			log.Debugf("agent(key: %s) timer channel was already drained, this is normal", ctx.key)
		}
	}
	timer.Reset(agentInactivityTimeout)
}

func (e *RemoteExecute) isHeartbeat(resp *api.RemoteExecResponse) bool {
	return resp.CommandResult == nil && resp.LinuxNamespaces == nil &&
		resp.Commands == nil && resp.Errmsg == nil
}

func (e *RemoteExecute) needLogHeartbeat(ctx *remoteExecContext) bool {
	return ctx.heartbeatCount%20 == 0
}

func (e *RemoteExecute) logHeartbeat(ctx *remoteExecContext, resp *api.RemoteExecResponse) {
	ctx.heartbeatCount++
	if e.needLogHeartbeat(ctx) {
		log.Infof("agent(key: %s) heartbeat count: %d", ctx.key, ctx.heartbeatCount)
		log.Infof("agent(key: %s) heartbeat command response: %s", ctx.key, resp.String())
	}
}

func (e *RemoteExecute) sendRequest(ctx *remoteExecContext, stream api.Synchronizer_RemoteExecuteServer, req *api.RemoteExecRequest) error {
	e.logRequest(ctx, req)
	if err := stream.Send(req); err != nil {
		log.Errorf("server failed to send request to agent(key: %s) , req: %#v, err: %v", ctx.key, req, err)
		return err
	}
	return nil
}

func (e *RemoteExecute) logResponse(resp *api.RemoteExecResponse, key string) {
	b, _ := json.Marshal(resp)
	log.Infof("agent(key: %s) response: %s", key, string(b))
}

func (e *RemoteExecute) logRequest(ctx *remoteExecContext, req *api.RemoteExecRequest) {
	if req.RequestId != nil && *req.RequestId == reqeustIDOfResponseToHeartbeat {
		return
	}
	b, _ := json.Marshal(req)
	log.Infof("request to agent(key: %s): %s", ctx.key, string(b))
}
