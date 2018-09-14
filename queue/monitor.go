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
	ch chan []interface{}

	DebugOn bool
	Name    string
}

func (m *Monitor) isDebugOn() bool {
	on := m.DebugOn
	return on
}

func (m *Monitor) debugSwitch(on bool) {
	log.Infof("Monitor[%s] change debug switch to %v", m.Name, on)
	m.DebugOn = on
}

func (m *Monitor) run(conn *net.UDPConn, port int) {
	for m.DebugOn {
		items := <-m.ch
		m.sendDebug(conn, port, items)
	}
}

func (m *Monitor) TurnOnDebug(conn *net.UDPConn, port int) {
	m.ch = make(chan []interface{}, 1000)
	m.debugSwitch(true)
	go m.run(conn, port)
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
		select {
		case m.ch <- items:
		default:
		}
	}
}

func (m *Monitor) init(name string) {
	m.Name = name
}
