package rpc

import (
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet/protobuf"
)

var log = logging.MustGetLogger("rpc")

const (
	NORMAL_EXIT_WITH_RESTART  = 2
	DEFAULT_SYN_INTERVAL_TIME = 10
)

type RpcHandle interface {
	RpcHandle(res *protobuf.SyncResponse)
}

type RpcWorker struct {
	bootTime       uint32
	rpcSession     RpcSession
	runtimeConfig  RuntimeConfig
	rpcHandle      []RpcHandle
	stop           bool
	configAccepted bool
}

func (w *RpcWorker) request() (*protobuf.SyncResponse, error) {
	request := protobuf.SyncRequest{
		BootTime:       proto.Uint32(w.bootTime),
		ConfigAccepted: proto.Bool(w.configAccepted),
	}
	return w.rpcSession.Request(&request)
}

func (w *RpcWorker) onResponse(resp *protobuf.SyncResponse) {
	if status := resp.GetStatus(); status != protobuf.Status_SUCCESS {
		log.Warning("Unsuccessful status:", resp)
		return
	}
	for _, handle := range w.rpcHandle {
		handle.RpcHandle(resp)
	}
}

func (w *RpcWorker) runOnce() {
	response, err := w.request()
	if err != nil {
		log.Warning(err)
		return
	}
	w.onResponse(response)
}

func (w *RpcWorker) run() {
	w.stop = false
	for !w.stop {
		w.runOnce()
		time.Sleep(w.runtimeConfig.SyncInterval)
	}
	w.rpcSession.Close()
}

func (w *RpcWorker) Start() {
	go w.run()
}

func (w *RpcWorker) Stop() {
	w.stop = true
}

func NewRpcWorker(session RpcSession, rpchandle []RpcHandle) *RpcWorker {
	return &RpcWorker{
		bootTime:       uint32(time.Now().Unix()),
		rpcSession:     session,
		runtimeConfig:  RuntimeConfig{SyncInterval: DEFAULT_SYN_INTERVAL_TIME * time.Second},
		rpcHandle:      rpchandle,
		configAccepted: true,
	}
}
