package synchronize

import (
	"net"
	"strconv"
	"time"

	api "github.com/metaflowys/metaflow/message/trident"
	context "golang.org/x/net/context"

	"github.com/metaflowys/metaflow/server/controller/trisolaris"
)

type NTPEvent struct{}

func NewNTPEvent() *NTPEvent {
	return &NTPEvent{}
}

func (e *NTPEvent) Query(ctx context.Context, in *api.NtpRequest) (*api.NtpResponse, error) {
	log.Infof("request ntp proxcy from ip: %s", in.GetCtrlIp())
	config := trisolaris.GetConfig()
	addr := net.JoinHostPort(config.Chrony.Host, strconv.Itoa(int(config.Chrony.Port)))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Error(err)
		return &api.NtpResponse{}, nil
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Error(err)
		return &api.NtpResponse{}, nil
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Duration(config.Chrony.Timeout) * time.Second)); err != nil {
		log.Error(err)
		return &api.NtpResponse{}, nil
	}
	request := in.GetRequest()
	if request == nil {
		log.Errorf("ntp query no request data from ip: %s", in.GetCtrlIp())
		return &api.NtpResponse{}, nil
	}
	_, err = conn.Write(request)
	if err != nil {
		log.Error("send ntp request failed", err)
		return &api.NtpResponse{}, nil
	}
	data := make([]byte, 4096)
	n, remoterAddr, err := conn.ReadFromUDP(data)
	if err != nil {
		log.Error("receive ntp response failed", remoterAddr, err)
		return &api.NtpResponse{}, nil
	}
	log.Debug("receive ntp response", remoterAddr, n)
	return &api.NtpResponse{
		Response: data[:n],
	}, nil
}
