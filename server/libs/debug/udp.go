/*
 * Copyright (c) 2022 Yunshan Networks
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

package debug

import (
	"bytes"
	"encoding/gob"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"
)

type ModuleId uint16
type ModuleOperate uint16

type RegisterCommmandLine func(moduleId ModuleId) *cobra.Command
type CommandLineProcess interface {
	RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer)
}

const (
	DEFAULT_LISTEN_PORT = 9528
	UDP_MAXLEN          = 9710
	MAX_PAYLOAD_LEN     = UDP_MAXLEN - 128 //发送时会封装为DebugMessage，净荷为DebugMessage的Args
	MODULE_MAX          = 32
)

var (
	hostIp       = "0.0.0.0"
	hostPort int = DEFAULT_LISTEN_PORT
	running      = false
	log          = logging.MustGetLogger(os.Args[0])

	recvHandlers     = [MODULE_MAX]CommandLineProcess{}
	registerHandlers = [MODULE_MAX]RegisterCommmandLine{}
)

type DebugMessage struct {
	Module, Operate uint16
	Result          uint32
	Args            []byte
}

func SetIpAndPort(ip string, port int) {
	hostIp = ip
	hostPort = port
}

func RecvFromServer(conn *net.UDPConn) (*bytes.Buffer, error) {
	data := make([]byte, UDP_MAXLEN)
	msg := DebugMessage{}

	if _, _, err := conn.ReadFrom(data); err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&msg); err != nil {
		return nil, err
	} else if msg.Result != 0 {
		return nil, errors.New("msg.Result != 0")
	}
	return bytes.NewBuffer(msg.Args[:]), nil
}

func SendToServer(module ModuleId, operate ModuleOperate, args *bytes.Buffer) (*net.UDPConn, *bytes.Buffer, error) {
	conn, err := net.Dial("udp4", hostIp+":"+strconv.Itoa(hostPort))
	if err != nil {
		return nil, nil, err
	}
	sendBuffer := bytes.Buffer{}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg := DebugMessage{Module: uint16(module), Operate: uint16(operate), Result: 0}
	if args != nil {
		msg.Args = args.Bytes()
	}
	encoder := gob.NewEncoder(&sendBuffer)
	if err := encoder.Encode(msg); err != nil {
		return conn.(*net.UDPConn), nil, err
	}

	conn.Write(sendBuffer.Bytes())

	var recv *bytes.Buffer
	if module > MODULE_MAX {
		recv, err = RecvFromServerMulti(conn.(*net.UDPConn))
	} else {
		recv, err = RecvFromServer(conn.(*net.UDPConn))
	}
	return conn.(*net.UDPConn), recv, err
}

func SendToClient(conn *net.UDPConn, remote *net.UDPAddr, result uint32, args *bytes.Buffer) {
	buffer := bytes.Buffer{}
	msg := DebugMessage{Module: 0, Result: result, Operate: 11}
	if args != nil {
		msg.Args = args.Bytes()
	}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(msg); err != nil {
		log.Error(err)
		return
	}

	if buffer.Len() > UDP_MAXLEN {
		log.Warningf("data.Len=%d buffer.Len=%d > %d", len(msg.Args), buffer.Len(), UDP_MAXLEN)
		return
	}
	conn.WriteToUDP(buffer.Bytes(), remote)
	return
}

func process(conn *net.UDPConn) {
	data := make([]byte, UDP_MAXLEN)
	msg := DebugMessage{}

	_, remote, err := conn.ReadFromUDP(data)
	if err != nil {
		return
	}
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err := decoder.Decode(&msg); err != nil {
		log.Error(err)
		return
	}
	if msg.Module < MODULE_MAX && recvHandlers[msg.Module] != nil {
		recvHandlers[msg.Module].RecvCommand(conn, remote, msg.Operate, bytes.NewBuffer(msg.Args[:]))
		return
	}
	if simpleHandlers[msg.Module] != nil {
		result := simpleHandlers[msg.Module].HandleSimpleCommand(msg.Operate, string(msg.Args))
		for i := 0; i < len(result); i += MAX_PAYLOAD_LEN {
			if i+MAX_PAYLOAD_LEN > len(result) {
				SendToClient(conn, remote, 0, bytes.NewBufferString(result[i:]))
			} else {
				SendToClient(conn, remote, 0, bytes.NewBufferString(result[i:i+MAX_PAYLOAD_LEN]))
			}
			// upd发送太快，对端接收不及时，会导致丢包，调试结果无法显示
			time.Sleep(10 * time.Millisecond)
		}
		// 补充发送"\n"用来指示客户端只要收到小于MAX_PAYLOAD_LEN的数据，就认为接收结束了
		if len(result) > 0 && len(result)%MAX_PAYLOAD_LEN == 0 {
			SendToClient(conn, remote, 0, bytes.NewBufferString("\n"))
		}
		return
	}
}

func debugListener() {
	go func() {
		addr := &net.UDPAddr{IP: net.ParseIP(hostIp), Port: hostPort}
		listener, err := net.ListenUDP("udp4", addr)
		if err != nil {
			log.Error(err)
			return
		}
		defer listener.Close()
		log.Infof("DebugListener <%v:%v>", hostIp, hostPort)
		for {
			process(listener)
		}
	}()
}

// server端注册命令处理
func Register(module ModuleId, process CommandLineProcess) {
	recvHandlers[module] = process
	if running == false {
		debugListener()
		running = true
	}
}

// client注册命令处理
func RegisterCommand(root *cobra.Command, moduleId ModuleId, handle RegisterCommmandLine) {
	root.AddCommand(handle(moduleId))
}
