package queue

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"time"

	"server/libs/debug"

	"github.com/yunshan/droplet/dropletctl"
)

type MonitorOperator interface {
	TurnOnDebug(conn *net.UDPConn, remote *net.UDPAddr)
	TurnOffDebug()
}

type ReferenceCountable interface {
	AddReferenceCount()
	SubReferenceCount() bool
}

type Unmarshaller func(interface{}) (interface{}, error)

type Monitor struct {
	ch chan []interface{}

	DebugOn bool
	Name    string

	unmarshaller Unmarshaller
}

func (m *Monitor) isDebugOn() bool {
	on := m.DebugOn
	return on
}

func (m *Monitor) run(conn *net.UDPConn, remote *net.UDPAddr) {
	start := time.Now()
	var counter int
	for m.DebugOn {
		counter++
		items := <-m.ch
		m.sendDebug(conn, remote, items)
		if time.Since(start) > time.Minute {
			m.DebugOn = false
			log.Infof("Monitor[%s] change debug switch to off for timeout(60s)", m.Name)
			debugSendMsg(conn, remote, fmt.Sprintf("Stop Monitor[%s] for timeout(60s), total receive %d msg", m.Name, counter))
		}
	}
}

func (m *Monitor) debugSwitch(on bool) {
	if m.DebugOn != on {
		log.Infof("Monitor[%s] change debug switch to %v", m.Name, on)
		m.DebugOn = on
	}
}

func debugSendMsg(conn *net.UDPConn, remote *net.UDPAddr, msg string) {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(msg); err != nil {
		log.Error(err)
	}
	debug.SendToClient(conn, remote, 0, &buffer)
}

func (m *Monitor) TurnOnDebug(conn *net.UDPConn, remote *net.UDPAddr) {
	m.ch = make(chan []interface{}, 1000)
	m.debugSwitch(true)
	go m.run(conn, remote)
}

func (m *Monitor) TurnOffDebug() {
	m.debugSwitch(false)
}

func (m *Monitor) unmarshal(item interface{}) interface{} {
	if m.unmarshaller != nil {
		unmarshalledItem, err := m.unmarshaller(item)
		if err != nil {
			log.Error("item unmarshal error", err)
			return nil
		}
		if _, ok := unmarshalledItem.(fmt.Stringer); !ok {
			log.Error("item.(fmt.Stringer) type assertions error.")
			return nil
		}
		return unmarshalledItem
	}
	return item
}

func (m *Monitor) sendDebug(conn *net.UDPConn, remote *net.UDPAddr, items []interface{}) {
	if _, ok := items[0].(fmt.Stringer); !ok && m.unmarshaller == nil {
		log.Debug("item.(fmt.Stringer) type assertions error.")
		return
	}
	for _, item := range items {
		buffer := bytes.Buffer{}
		if item = m.unmarshal(item); item == nil {
			break
		}
		message := item.(fmt.Stringer).String()
		if len(message) > dropletctl.DEBUG_MESSAGE_LEN-8 {
			message = message[:dropletctl.DEBUG_MESSAGE_LEN-8-3] + "..."
		}
		encoder := gob.NewEncoder(&buffer)
		if err := encoder.Encode(message); err != nil {
			log.Error(err)
			break
		}
		debug.SendToClient(conn, remote, 0, &buffer)
	}
}

func (m *Monitor) send(items []interface{}) {
	if m.isDebugOn() && len(items) > 0 {
		if _, ok := items[0].(ReferenceCountable); !ok {
			log.Errorf("queue[%s] recv invalid data.", m.Name)
			return
		}
		for _, item := range items {
			if item != nil {
				item.(ReferenceCountable).AddReferenceCount()
			}
		}

		select {
		case m.ch <- items:
		default:
		}
	}
}

func (m *Monitor) init(name string, unmarshaller Unmarshaller) {
	m.Name = name
	m.unmarshaller = unmarshaller
}
