package dropletctl

import (
	"bytes"
	"encoding/gob"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/op/go-logging"
)

const (
	UDP_MAXLEN               = 8192
	DROPLET_MESSAGE_ARGS_LEN = 8000
)

type DropletMessage struct {
	Module, Operate uint16
	Result          uint32
	Args            [DROPLET_MESSAGE_ARGS_LEN]byte
}

var log = logging.MustGetLogger(os.Args[0])
var running bool = false

func RecvFromDroplet(conn *net.UDPConn) (*bytes.Buffer, error) {
	data := make([]byte, UDP_MAXLEN)
	msg := DropletMessage{}

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

func SendToDroplet(module DropletCtlModuleId, operate DropletCtlModuleOperate, args *bytes.Buffer) (*net.UDPConn, *bytes.Buffer, error) {
	conn, err := net.Dial("udp4", DROPLETCTL_IP+":"+strconv.Itoa(DROPLETCTL_PORT))
	if err != nil {
		return nil, nil, err
	}
	sendBuffer := bytes.Buffer{}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg := DropletMessage{Module: uint16(module), Operate: uint16(operate), Result: 0}
	if args != nil {
		args.Read(msg.Args[:])
	}
	encoder := gob.NewEncoder(&sendBuffer)
	if err := encoder.Encode(msg); err != nil {
		return conn.(*net.UDPConn), nil, err
	}

	conn.Write(sendBuffer.Bytes())
	recv, err := RecvFromDroplet(conn.(*net.UDPConn))
	return conn.(*net.UDPConn), recv, err
}

func SendToDropletCtl(conn *net.UDPConn, port int, result uint32, args *bytes.Buffer) {
	if args != nil && args.Len() > DROPLET_MESSAGE_ARGS_LEN {
		log.Warningf("len(args) > %v", DROPLET_MESSAGE_ARGS_LEN)
		return
	}
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
	data := make([]byte, UDP_MAXLEN)
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
