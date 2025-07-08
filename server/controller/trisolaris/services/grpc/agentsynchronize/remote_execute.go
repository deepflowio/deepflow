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
	cmdInactivityTimeout = 1 * time.Minute
)

func newRemoteExecContext(streamCtx context.Context) *remoteExecContext {
	streamCtx, cancel := context.WithCancel(streamCtx)
	return &remoteExecContext{
		streamCtx:    streamCtx,
		streamCancel: cancel,
		errChan:      make(chan error, 1),
		initDoneChan: make(chan struct{}),
	}
}

type remoteExecContext struct {
	streamCtx    context.Context // stream context
	streamCancel context.CancelFunc

	heartbeatCount uint32 // used to sample the agent's heartbeats

	key          string // agent key, format: ip-mac
	isFirstRecv  bool   // whether the first message has been received
	manager      *service.CMDManager
	wg           sync.WaitGroup
	errChan      chan error    // channel to handle errors
	initDoneChan chan struct{} // channel to signal initialization done
}

func (e *RemoteExecute) RemoteExecute(stream api.Synchronizer_RemoteExecuteServer) error {
	ctx := newRemoteExecContext(stream.Context())
	defer ctx.streamCancel()

	ctx.wg.Add(1)
	defer func() {
		ctx.wg.Wait()
		service.RemoveAllFromCMDManager(ctx.key)
	}()

	go e.receiveAndHandle(ctx, stream)

	<-ctx.initDoneChan
	log.Infof("[remote-exec] agent(key: %s) init done", ctx.key)

	return e.waitAndSend(ctx, stream)
}

func (e *RemoteExecute) receiveAndHandle(
	ctx *remoteExecContext,
	stream api.Synchronizer_RemoteExecuteServer,
) {
	defer func() {
		log.Infof("[remote-exec] agent(key: %s) remote exec stream receive goroutine done", ctx.key)
		ctx.wg.Done()
		if r := recover(); r != nil {
			e.handlePanic(ctx)
		}
	}()

	inactivityTimer := time.NewTimer(cmdInactivityTimeout)
	defer inactivityTimer.Stop()

	for {
		select {
		case <-ctx.streamCtx.Done():
			log.Infof("[remote-exec] context done, agent(key: %s), context err: %v", ctx.key, ctx.streamCtx.Err())
			return
		case <-inactivityTimer.C:
			e.handleInactivityTimeout(ctx)
			return
		default:
			resp, err := stream.Recv()
			// Handle any errors that occur during stream reception
			// if server restart, an io.EOF error may be received
			if err == io.EOF {
				e.handleStreamErr(ctx, err)
				return
			}

			e.resetTimer(inactivityTimer)
			e.initCtxAndHandleResp(ctx, resp, err)
		}
	}
}

func (e *RemoteExecute) initCtxAndHandleResp(ctx *remoteExecContext, resp *api.RemoteExecResponse, err error) {
	if resp == nil {
		return
	}

	log.Debugf("[remote-exec] agent command response: %s", resp.String())

	if resp.AgentId == nil {
		log.Warningf("[remote-exec] get null agent info from response: %s", resp.String())
		return
	}

	ctx.key = resp.AgentId.GetIp() + "-" + resp.AgentId.GetMac()

	if !ctx.isFirstRecv {
		ctx.isFirstRecv = true
		log.Infof("[remote-exec] agent(key: %s) called me for the first time", ctx.key)
	}

	if ctx.manager == nil {
		log.Infof("[remote-exec] agent(key: %s) cmd manager not found, new one manager", ctx.key)
		ctx.manager = service.AddToCMDManagerIfNotExist(ctx.key, uint64(1))
		ctx.initDoneChan <- struct{}{}
	}

	service.LockAgentCMD()
	defer service.UnlockAgentCMD()

	ctx.manager = service.GetAgentCMDManagerWithoutLock(ctx.key)
	if ctx.manager == nil {
		log.Errorf("[remote-exec] agent(key: %s) cmd manager not found", ctx.key)
		return
	}

	if e.isHeartbeat(resp) {
		e.logHeartbeat(ctx, resp)
		ctx.manager.ExecCH <- &api.RemoteExecRequest{RequestId: proto.Uint64(0)}
		return
	}

	if err != nil {
		e.handleStreamErr(ctx, err)
		return
	}

	e.handleResponse(ctx, resp)
}

func (e *RemoteExecute) handleResponse(ctx *remoteExecContext, resp *api.RemoteExecResponse) {
	if resp.RequestId == nil {
		log.Errorf("[remote-exec] agent(key: %s) command resp request id not found", ctx.key, resp.RequestId)
		return
	}

	cmdResp := service.GetAgentCMDRespWithoutLock(ctx.key, *resp.RequestId)
	if cmdResp == nil {
		log.Errorf("[remote-exec] agent(key: %s, request id: %v) remote exec map not found", ctx.key, resp.RequestId)
		return
	}

	e.logResponse(resp, ctx.key)

	if resp.Errmsg != nil {
		e.handleRespErrmsg(ctx.key, resp, cmdResp)
		return
	}

	if len(resp.LinuxNamespaces) > 0 {
		e.handleRespLinuxNamespaces(ctx.key, resp, cmdResp)
		return
	}

	if len(resp.Commands) > 0 {
		e.handleRespCommands(ctx.key, resp, cmdResp)
		return
	}

	e.handleRespCommandResult(ctx.key, resp, cmdResp)
}

func (e *RemoteExecute) handleRespErrmsg(key string, resp *api.RemoteExecResponse, cmdResp *service.CMDResp) {
	log.Errorf("[remote-exec] agent(key: %s) run command error: %s", key, *resp.Errmsg)
	service.AppendErrorMessageWithoutLock(key, *resp.RequestId, resp.Errmsg)

	result := resp.CommandResult
	if result == nil || result.Content == nil {
		cmdResp.ExecDoneCH <- struct{}{}
		return
	}
	service.AppendContentWithoutLock(key, *resp.RequestId, result.Content)

	if result.Md5 != nil {
		cmdResp.ExecDoneCH <- struct{}{}
		return
	}
}

func (e *RemoteExecute) handleRespLinuxNamespaces(key string, resp *api.RemoteExecResponse, cmdResp *service.CMDResp) {
	if len(service.GetNamespacesWithoutLock(key, *resp.RequestId)) > 0 {
		service.InitNamespacesWithoutLock(key, *resp.RequestId, resp.LinuxNamespaces)
	} else {
		service.AppendNamespacesWithoutLock(key, *resp.RequestId, resp.LinuxNamespaces)
	}
	cmdResp.LinuxNamespaceDoneCH <- struct{}{}
}

func (e *RemoteExecute) handleRespCommands(key string, resp *api.RemoteExecResponse, cmdResp *service.CMDResp) {
	if len(service.GetCommandsWithoutLock(key, *resp.RequestId)) > 0 {
		service.InitCommandsWithoutLock(key, *resp.RequestId, resp.Commands)
	} else {
		service.AppendCommandsWithoutLock(key, *resp.RequestId, resp.Commands)
	}
	cmdResp.RemoteCMDDoneCH <- struct{}{}
}

func (e *RemoteExecute) handleRespCommandResult(key string, resp *api.RemoteExecResponse, cmdResp *service.CMDResp) {
	result := resp.CommandResult
	if resp.CommandResult == nil {
		return
	}

	if result.Content != nil {
		service.AppendContentWithoutLock(key, *resp.RequestId, result.Content)
	}
	if result.Md5 != nil {
		cmdResp.ExecDoneCH <- struct{}{}
		return
	}
}

func (e *RemoteExecute) waitAndSend(
	ctx *remoteExecContext,
	stream api.Synchronizer_RemoteExecuteServer,
) error {
	for {
		if ctx.manager == nil {
			err := fmt.Errorf("[remote-exec] agent(key: %s) cmd manager not found", ctx.key)
			log.Error(err)
			return err
		}

		select {
		case <-ctx.streamCtx.Done():
			log.Infof("[remote-exec] context done, agent(key: %s), context err: %v", ctx.key, ctx.streamCtx.Err())
			return ctx.streamCtx.Err()
		case err := <-ctx.errChan:
			log.Error(err)
			return err
		case req, ok := <-ctx.manager.ExecCH:
			if !ok {
				err := fmt.Errorf("[remote-exec] agent(key: %s) cmd manager exec channel is closed", ctx.key)
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
	errMsg := fmt.Sprintf("[remote-exec] recovered in RemoteExecute: %s", buf[:n])
	log.Errorf(errMsg)
	ctx.errChan <- fmt.Errorf(errMsg)
}

func (e *RemoteExecute) handleInactivityTimeout(ctx *remoteExecContext) {
	errMsg := fmt.Errorf("[remote-exec] no message received for %vs, closing connection for agent(key: %s)",
		cmdInactivityTimeout.Seconds(), ctx.key)
	log.Error(errMsg)
	ctx.errChan <- errMsg
}

func (e *RemoteExecute) handleStreamErr(ctx *remoteExecContext, err error) {
	if err == io.EOF {
		log.Errorf("[remote-exec] agent(key: %s) command stream error: %v", ctx.key, err)
		ctx.errChan <- err
	}
}

// resetTimer attempts to stop the inactivity timer and reset it to its original duration.
// If the timer has already expired, it drains the channel to prevent blocking.
func (e *RemoteExecute) resetTimer(timer *time.Timer) {
	if !timer.Stop() {
		<-timer.C
	}
	timer.Reset(cmdInactivityTimeout)
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
		log.Infof("[remote-exec] agent(key: %s) heartbeat count: %d", ctx.key, ctx.heartbeatCount)
		log.Infof("[remote-exec] agent heartbeat command response: %s", resp.String())
	}
}

func (e *RemoteExecute) sendRequest(ctx *remoteExecContext, stream api.Synchronizer_RemoteExecuteServer, req *api.RemoteExecRequest) error {
	e.logRequest(ctx, req)
	if err := stream.Send(req); err != nil {
		log.Errorf("[remote-exec] failed to send cmd to agent: %s, req: %#v", err.Error(), req)
		return err
	}
	return nil
}

func (e *RemoteExecute) logResponse(resp *api.RemoteExecResponse, key string) {
	b, _ := json.Marshal(resp)
	log.Infof("[remote-exec] agent(key: %s) response: %s", key, string(b))
}

func (e *RemoteExecute) logRequest(ctx *remoteExecContext, req *api.RemoteExecRequest) {
	if req.RequestId != nil && *req.RequestId == 0 && !e.needLogHeartbeat(ctx) { // agent heartbeat request id is 0
		return
	}
	b, _ := json.Marshal(req)
	log.Infof("[remote-exec] agent(key: %s) request: %s", ctx.key, string(b))
}
