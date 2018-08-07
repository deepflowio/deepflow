package dpctl

import (
	"bytes"
	"encoding/gob"
	"errors"
	"net"
	"os"

	"github.com/op/go-logging"
)

type DropletMessage struct {
	Module, Operate uint16
	Result          uint32
	Arg             [1024]byte
}

var log = logging.MustGetLogger(os.Args[0])
var running bool = false

func resultFromDroplet(conn *net.UDPConn) (*bytes.Buffer, error) {
	data := make([]byte, 1500)
	msg := DropletMessage{}

	if _, _, err := conn.ReadFromUDP(data); err != nil {
		return nil, err
	}

	buff := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buff)
	if err := decoder.Decode(&msg); err != nil {
		return nil, err
	} else if msg.Result != 0 {
		return nil, errors.New("msg.Result != 0")
	}
	return bytes.NewBuffer(msg.Arg[:]), nil
}

func SendToDroplet(module DropletCtrlModuleId, operate DropletCtrlModuleOperate, arg *bytes.Buffer) (*bytes.Buffer, error) {
	dst := &net.UDPAddr{IP: net.ParseIP(DPCTL_IP), Port: DPCTL_PORT}

	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return nil, err
	}
	sendBuff := bytes.Buffer{}

	msg := DropletMessage{Module: uint16(module), Operate: uint16(operate), Result: 0}
	if arg != nil {
		arg.Read(msg.Arg[:])
	}
	encoder := gob.NewEncoder(&sendBuff)
	if err := encoder.Encode(msg); err != nil {
		return nil, err
	}

	conn.Write(sendBuff.Bytes())
	return resultFromDroplet(conn)
}

func SendToDropletCtrl(conn *net.UDPConn, port int, result uint32, arg *bytes.Buffer) {
	dst := &net.UDPAddr{IP: net.ParseIP(DPCTL_IP), Port: port}
	buff := bytes.Buffer{}
	msg := DropletMessage{Module: 0, Result: result, Operate: 11}
	if arg != nil {
		arg.Read(msg.Arg[:])
	}
	encoder := gob.NewEncoder(&buff)
	if err := encoder.Encode(msg); err != nil {
		log.Error(err)
		return
	}
	conn.WriteToUDP(buff.Bytes(), dst)
	return
}

func process(conn *net.UDPConn) {
	data := make([]byte, 1500)
	msg := DropletMessage{}

	_, remote, err := conn.ReadFromUDP(data)
	if err != nil {
		return
	}
	buff := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buff)
	if err := decoder.Decode(&msg); err != nil {
		log.Error(err)
		return
	}
	RecvHandlers[msg.Module].RecvCommand(conn, remote.Port, msg.Operate, bytes.NewBuffer(msg.Arg[:]))
}

func DropletCtrlListener() {
	addr := &net.UDPAddr{IP: net.ParseIP(DPCTL_IP), Port: DPCTL_PORT}
	go func() {
		listener, err := net.ListenUDP("udp4", addr)
		if err != nil {
			log.Error(err)
			return
		}
		defer listener.Close()
		log.Infof("DropletCtrlListener <%v:%v>", DPCTL_IP, DPCTL_PORT)
		for {
			process(listener)
		}
	}()
}

func Register(module DropletCtrlModuleId, process CommandLineProcess) {
	RecvHandlers[module] = process
	if running == false {
		DropletCtrlListener()
		running = true
	}
}

func RegisterCommand(module DropletCtrlModuleId, cmd RegisterCommmandLine) {
	RegisterHandlers[module] = cmd
}
