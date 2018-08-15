package queue

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"

	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
)

type DebugMessage struct {
	Data fmt.Stringer
}

type Queue struct {
	queue.OverwriteQueue

	ch chan []interface{}

	DebugOn bool
	Name    string

	Data fmt.Stringer
}

func (q *Queue) isDebugOn() bool {
	on := q.DebugOn
	return on
}

func (q *Queue) debugSwitch(on bool) {
	log.Infof("Queue[%s] change debug switch to %v", q.Name, on)
	q.DebugOn = on
}

func (q *Queue) run(conn *net.UDPConn, port int) {
	for q.DebugOn {
		items := <-q.ch
		q.sendDebug(conn, port, items)
	}
}

func (q *Queue) TurnOnDebug(conn *net.UDPConn, port int) {
	q.ch = make(chan []interface{}, 1000)
	q.debugSwitch(true)
	go q.run(conn, port)
}

func (q *Queue) TurnOffDebug() {
	q.debugSwitch(false)
}

func (q *Queue) sendDebug(conn *net.UDPConn, port int, items []interface{}) {
	if _, ok := items[0].(fmt.Stringer); !ok {
		log.Error("item.(fmt.Stringer) type assertions error.")
		return
	}
	for _, item := range items {
		buffer := bytes.Buffer{}
		gob.Register(q.Data)
		message := DebugMessage{Data: item.(fmt.Stringer)}
		encoder := gob.NewEncoder(&buffer)
		if err := encoder.Encode(message); err != nil {
			log.Error(err)
			break
		}
		dropletctl.SendToDropletCtl(conn, port, 0, &buffer)
	}
}

func (q *Queue) Put(items ...interface{}) error {
	if q.isDebugOn() {
		q.ch <- items
	}
	return q.OverwriteQueue.Put(items...)
}
