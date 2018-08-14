package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"gitlab.x.lan/yunshan/droplet/protobuf"
)

type RpcSession interface {
	Request(*protobuf.SyncRequest) (*protobuf.SyncResponse, error)
	Close()
}

type GRpcInitiator struct {
	ips     []net.IP
	port    uint16
	timeout time.Duration

	ipIndex      int
	clientConn   *grpc.ClientConn
	syncClient   protobuf.SynchronizerClient
	synchronized bool
}

func NewGRpcInitiator(ips []net.IP, port uint16, timeout time.Duration) RpcSession {
	return &GRpcInitiator{
		ips:          ips,
		port:         port,
		timeout:      timeout,
		ipIndex:      -1,
		synchronized: true, // 避免启动后连接服务器失败时不打印
	}
}

func (r *GRpcInitiator) Request(request *protobuf.SyncRequest) (*protobuf.SyncResponse, error) {
	if r.clientConn == nil {
		r.nextServer()
	}
	for i := 0; i < len(r.ips); i++ {
		ctx, _ := context.WithTimeout(context.Background(), time.Second)
		response, err := r.syncClient.Sync(ctx, request)
		if err != nil {
			if r.synchronized {
				r.synchronized = false
				log.Warningf("Sync from server %s failed, reason: %s", r.ips[r.ipIndex], err.Error())
			}
			r.nextServer()
			continue
		}
		if !r.synchronized {
			r.synchronized = true
			log.Info("Synchronized to server", r.ips[r.ipIndex])
		}
		return response, nil
	}
	return nil, errors.New("No reachable server")
}

func (r *GRpcInitiator) nextServer() {
	r.Close()
	r.ipIndex++
	if r.ipIndex >= len(r.ips) {
		r.ipIndex = 0
	}
	server := fmt.Sprintf("%s:%d", r.ips[r.ipIndex], r.port)
	clientConn, err := grpc.Dial(server, grpc.WithInsecure(), grpc.WithTimeout(r.timeout))
	if err != nil { // 这里的错误应该是指创建连接失败而非连接失败，因此只好自杀
		log.Error(err)
		os.Exit(1)
	}
	r.clientConn = clientConn
	r.syncClient = protobuf.NewSynchronizerClient(clientConn)
}

func (r *GRpcInitiator) Close() {
	if r.clientConn != nil {
		r.clientConn.Close()
		r.clientConn = nil
	}
}
