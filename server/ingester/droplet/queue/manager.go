package queue

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"
	"gitlab.yunshan.net/yunshan/droplet-libs/datatype"
	"gitlab.yunshan.net/yunshan/droplet-libs/debug"
	"gitlab.yunshan.net/yunshan/droplet-libs/queue"
)

var log = logging.MustGetLogger("queue_manager")

type Manager struct {
	queues map[string]MonitorOperator
}

const (
	QUEUE_CMD_SHOW = iota
	QUEUE_CMD_MONITOR_ON
	QUEUE_CMD_MONITOR_OFF
	QUEUE_CMD_CLEAR
)

func NewManager(module debug.ModuleId) *Manager {
	manager := &Manager{}
	manager.queues = make(map[string]MonitorOperator)
	debug.Register(module, manager)
	return manager
}

func (m *Manager) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	buffer := bytes.Buffer{}
	switch operate {
	case QUEUE_CMD_SHOW:
		names := make([]string, 0, len(m.queues))
		for name, _ := range m.queues {
			names = append(names, name)
		}
		encoder := gob.NewEncoder(&buffer)
		if err := encoder.Encode(names); err != nil {
			log.Error(err)
			return
		}
		debug.SendToClient(conn, remote, 0, &buffer)
		break
	case QUEUE_CMD_MONITOR_ON:
		name := ""
		decoder := gob.NewDecoder(arg)
		if err := decoder.Decode(&name); err != nil {
			log.Error(err)
			return
		}
		if m.queues[name] == nil {
			log.Errorf("queue[%s] not found.", name)
			return
		}
		m.queues[name].TurnOnDebug(conn, remote)
		debug.SendToClient(conn, remote, 0, nil)
		break
	case QUEUE_CMD_MONITOR_OFF:
		name := ""
		decoder := gob.NewDecoder(arg)
		if err := decoder.Decode(&name); err != nil {
			log.Error(err)
			return
		}
		if m.queues[name] == nil {
			log.Errorf("queue[%s] not found.", name)
			return
		}
		m.queues[name].TurnOffDebug()
		break
	case QUEUE_CMD_CLEAR:
		for _, queue := range m.queues {
			queue.TurnOffDebug()
		}
		debug.SendToClient(conn, remote, 0, nil)
	default:
		log.Warningf("Trident Adapter recv unknown command(%v).", operate)
	}
}

func (m *Manager) NewQueue(name string, size int, options ...queue.Option) *Queue {
	q := &Queue{}
	q.Init(name, size, nil, options...)
	m.queues[name] = q
	return q
}

func (m *Manager) NewQueues(name string, size, count, userCount int, options ...queue.Option) *MultiQueue {
	q := &MultiQueue{}
	q.Init(name, size, count, userCount, nil, options...)
	m.queues[name] = q
	return q
}

func (m *Manager) NewQueueUnmarshal(name string, size int, unmarshaller Unmarshaller, options ...queue.Option) *Queue {
	q := &Queue{}
	q.Init(name, size, unmarshaller, options...)
	m.queues[name] = q
	return q
}

func (m *Manager) NewQueuesUnmarshal(name string, size, count, userCount int, unmarshaller Unmarshaller, options ...queue.Option) *MultiQueue {
	q := &MultiQueue{}
	q.Init(name, size, count, userCount, unmarshaller, options...)
	m.queues[name] = q
	return q
}

func sendCmdOnly(moduleId debug.ModuleId, operate int, arg *bytes.Buffer) (*net.UDPConn, *bytes.Buffer, error) {
	conn, result, err := debug.SendToServer(moduleId, debug.ModuleOperate(operate), arg)
	if err != nil {
		return conn, nil, err
	}
	return conn, result, nil
}

func sendCmd(moduleId debug.ModuleId, operate int, arg *bytes.Buffer, out interface{}) bool {
	_, result, err := sendCmdOnly(moduleId, operate, arg)
	if err != nil {
		fmt.Println(err)
		return false
	}
	decoder := gob.NewDecoder(result)
	if err = decoder.Decode(out); err != nil {
		fmt.Printf("%v: %v\n", err, out)
		return false
	}
	return true
}

func queueOperate(moduleId debug.ModuleId, name string, operate int) *net.UDPConn {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(name); err != nil {
		fmt.Printf("%v: %s\n", err, name)
		return nil
	}

	conn, _, err := sendCmdOnly(moduleId, operate, &buffer)
	if err != nil {
		return nil
	}
	return conn
}

func isNotTimeout(err error) bool {
	return !strings.Contains(err.Error(), "timeout")
}

func recvDebugMsg(moduleId debug.ModuleId, conn *net.UDPConn, name string) {
	sigs := make(chan os.Signal, 10)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGKILL, syscall.SIGQUIT, syscall.SIGSTOP)
	var message string
	for {
		select {
		case sig := <-sigs:
			queueOperate(moduleId, name, QUEUE_CMD_MONITOR_OFF)
			fmt.Printf("signal %v\n", sig)
			conn.Close()
			return
		default:
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buffer, err := debug.RecvFromServer(conn)
			if err != nil {
				if isNotTimeout(err) {
					queueOperate(moduleId, name, QUEUE_CMD_MONITOR_OFF)
					fmt.Printf("dropletctl.RecvFromDroplet: %v\n", err)
					return
				}
				break
			}

			decoder := gob.NewDecoder(buffer)
			if err := decoder.Decode(&message); err != nil {
				queueOperate(moduleId, name, QUEUE_CMD_MONITOR_OFF)
				fmt.Printf("decoder.Decode: %v\n", err)
				return
			}
			fmt.Printf("%s\n", message)
		}
	}
}

func RegisterCommand(moduleId debug.ModuleId, queueNames []string) *cobra.Command {
	gob.Register(&datatype.MetaPacket{})
	gob.Register(&datatype.TaggedMetering{})

	queue := &cobra.Command{
		Use:   "queue",
		Short: "monitor queue module",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'show | monitor'.\n")
		},
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "show queue list",
		Run: func(cmd *cobra.Command, args []string) {
			names := []string{}
			if sendCmd(moduleId, QUEUE_CMD_SHOW, nil, &names) {
				sort.Strings(names)
				fmt.Println("Queue List:")
				for i, name := range names {
					fmt.Printf("\t%3d:				%s\n", i+1, name)
				}
			}
		},
	}
	monitor := &cobra.Command{
		Use:       "monitor {name}",
		Short:     "monitor queue put data",
		ValidArgs: queueNames,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println("please run with '{queue-name}'.")
				return
			}
			conn := queueOperate(moduleId, args[0], QUEUE_CMD_MONITOR_ON)
			if conn != nil {
				recvDebugMsg(moduleId, conn, args[0])
			}
		},
	}
	clear := &cobra.Command{
		Use:   "clear",
		Short: "clear all queue",
		Run: func(cmd *cobra.Command, args []string) {
			sendCmdOnly(moduleId, QUEUE_CMD_CLEAR, nil)
		},
	}
	queue.AddCommand(show)
	queue.AddCommand(monitor)
	queue.AddCommand(clear)
	return queue
}
