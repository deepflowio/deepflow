package queue

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
)

type DebugMessage struct {
	Data string
}

type MonitorOperator interface {
	TurnOnDebug(conn *net.UDPConn, port int)
	TurnOffDebug()
}

type Monitor struct {
	DebugOn bool
	Name    string

	conn *net.UDPConn
	port int
}

func (m *Monitor) isDebugOn() bool {
	on := m.DebugOn
	return on
}

func (m *Monitor) debugSwitch(on bool) {
	log.Infof("Monitor[%s] change debug switch to %v", m.Name, on)
	m.DebugOn = on
}

func (m *Monitor) TurnOnDebug(conn *net.UDPConn, port int) {
	m.conn = conn
	m.port = port
	m.debugSwitch(true)
}

func (m *Monitor) TurnOffDebug() {
	m.debugSwitch(false)
}

func (m *Monitor) sendDebug(conn *net.UDPConn, port int, items []interface{}) {
	if _, ok := items[0].(fmt.Stringer); !ok {
		log.Error("item.(fmt.Stringer) type assertions error.")
		return
	}
	for _, item := range items {
		buffer := bytes.Buffer{}
		message := DebugMessage{Data: item.(fmt.Stringer).String()}
		encoder := gob.NewEncoder(&buffer)
		if err := encoder.Encode(message); err != nil {
			log.Error(err)
			break
		}
		dropletctl.SendToDropletCtl(conn, port, 0, &buffer)
	}
}

func (m *Monitor) send(items []interface{}) {
	if m.isDebugOn() && len(items) > 0 {
		m.sendDebug(m.conn, m.port, items)
	}
}

func (m *Monitor) init(name string) {
	m.Name = name
}
