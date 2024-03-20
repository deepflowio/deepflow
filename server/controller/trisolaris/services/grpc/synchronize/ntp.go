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
	"net"
	"strconv"
	"time"

	api "github.com/deepflowio/deepflow/message/trident"
	context "golang.org/x/net/context"

	"github.com/deepflowio/deepflow/server/controller/trisolaris"
)

type NTPEvent struct{}

func NewNTPEvent() *NTPEvent {
	return &NTPEvent{}
}

var EmptyNtpResponse = &api.NtpResponse{}

func (e *NTPEvent) Query(ctx context.Context, in *api.NtpRequest) (*api.NtpResponse, error) {
	log.Infof("request ntp proxcy from ip: %s", in.GetCtrlIp())
	config := trisolaris.GetConfig()
	addr := net.JoinHostPort(config.Chrony.Host, strconv.Itoa(int(config.Chrony.Port)))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Error(err)
		return EmptyNtpResponse, nil
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Error(err)
		return EmptyNtpResponse, nil
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Duration(config.Chrony.Timeout) * time.Second)); err != nil {
		log.Error(err)
		return EmptyNtpResponse, nil
	}
	request := in.GetRequest()
	if request == nil {
		log.Errorf("ntp query no request data from ip: %s", in.GetCtrlIp())
		return EmptyNtpResponse, nil
	}
	_, err = conn.Write(request)
	if err != nil {
		log.Error("send ntp request failed", err)
		return EmptyNtpResponse, nil
	}
	data := make([]byte, 4096)
	n, remoterAddr, err := conn.ReadFromUDP(data)
	if err != nil {
		log.Error("receive ntp response failed", remoterAddr, err)
		return EmptyNtpResponse, nil
	}
	log.Debug("receive ntp response", remoterAddr, n)
	return &api.NtpResponse{
		Response: data[:n],
	}, nil
}
