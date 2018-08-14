package dropletctl

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
	Args            [1024]byte
}

var log = logging.MustGetLogger(os.Args[0])
var running bool = false

func resultFromDroplet(conn *net.UDPConn) (*bytes.Buffer, error) {
	data := make([]byte, 1500)
	msg := DropletMessage{}

	if _, _, err := conn.ReadFromUDP(data); err != nil {
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

func SendToDroplet(module DropletCtlModuleId, operate DropletCtlModuleOperate, args *bytes.Buffer) (*bytes.Buffer, error) {
	dst := &net.UDPAddr{IP: net.ParseIP(DROPLETCTL_IP), Port: DROPLETCTL_PORT}

	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return nil, err
	}
	sendBuffer := bytes.Buffer{}

	msg := DropletMessage{Module: uint16(module), Operate: uint16(operate), Result: 0}
	if args != nil {
		args.Read(msg.Args[:])
	}
	encoder := gob.NewEncoder(&sendBuffer)
	if err := encoder.Encode(msg); err != nil {
		return nil, err
	}

	conn.Write(sendBuffer.Bytes())
	return resultFromDroplet(conn)
}

func SendToDropletCtl(conn *net.UDPConn, port int, result uint32, args *bytes.Buffer) {
	dst := &net.UDPAddr{IP: net.ParseIP(DROPLETCTL_IP), Port: port}
	buffer := bytes.Buffer{}
	msg := DropletMessage{Module: 0, Result: result, Operate: 11}
	if args != nil {
		args.Read(msg.Args[:])
	}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(msg); err != nil {
		log.Error(err)
		return
	}
	conn.WriteToUDP(buffer.Bytes(), dst)
	return
}

func process(conn *net.UDPConn) {
	data := make([]byte, 1500)
	msg := DropletMessage{}

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
	RecvHandlers[msg.Module].RecvCommand(conn, remote.Port, msg.Operate, bytes.NewBuffer(msg.Args[:]))
}

func DropletCtlListener() {
	addr := &net.UDPAddr{IP: net.ParseIP(DROPLETCTL_IP), Port: DROPLETCTL_PORT}
	go func() {
		listener, err := net.ListenUDP("udp4", addr)
		if err != nil {
			log.Error(err)
			return
		}
		defer listener.Close()
		log.Infof("DropletCtlListener <%v:%v>", DROPLETCTL_IP, DROPLETCTL_PORT)
		for {
			process(listener)
		}
	}()
}

func Register(module DropletCtlModuleId, process CommandLineProcess) {
	RecvHandlers[module] = process
	if running == false {
		DropletCtlListener()
		running = true
	}
}

func RegisterCommand(module DropletCtlModuleId, cmd RegisterCommmandLine) {
	RegisterHandlers[module] = cmd
}
