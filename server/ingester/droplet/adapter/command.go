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

package adapter

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/server/libs/debug"
)

const (
	ADAPTER_CMD_SHOW = iota
	ADAPTER_CMD_STATUS
)

type command struct {
	tridentAdapter *TridentAdapter
}

func (c *command) init(tridentAdapter *TridentAdapter) {
	c.tridentAdapter = tridentAdapter
}

func (c *command) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	buff := bytes.Buffer{}
	adapter := c.tridentAdapter
	switch operate {
	case ADAPTER_CMD_SHOW:
		encoder := gob.NewEncoder(&buff)
		counter := adapter.GetStatsCounter().(*PacketCounter)
		if err := encoder.Encode(counter); err != nil {
			log.Error(err)
			return
		}
		debug.SendToClient(conn, remote, 0, &buff)
		break
	case ADAPTER_CMD_STATUS:
		encoder := gob.NewEncoder(&buff)
		status := ""
		instances := adapter.GetInstances()
		for _, instance := range instances {
			for i := 0; i < TRIDENT_DISPATCHER_MAX; i++ {
				dispatcher := &instance.dispatchers[i]
				if dispatcher.cache != nil {
					status += fmt.Sprintf("Host: %16s Index: %2d Seq: %10d Drop: %10d Timestamp: %30s\n",
						instance.ip, i, dispatcher.seq, dispatcher.dropped,
						time.Unix(int64(dispatcher.maxTimestamp/time.Second), 0))
				}
			}
		}

		if err := encoder.Encode(status); err != nil {
			log.Error(err)
			return
		}
		debug.SendToClient(conn, remote, 0, &buff)
	default:
		log.Warningf("Trident Adapter recv unknown command(%v).", operate)
	}
}

func CommmandGetResult(moduleId debug.ModuleId, operate uint16, output interface{}) bool {
	_, result, err := debug.SendToServer(moduleId, debug.ModuleOperate(operate), nil)
	if err != nil {
		log.Warning(err)
		return false
	}
	decoder := gob.NewDecoder(result)
	if err = decoder.Decode(output); err != nil {
		log.Error(err)
		return false
	}
	return true
}

func RegisterCommand(moduleId debug.ModuleId) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "adapter",
		Short: "config droplet adapter module",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'show'.\n")
		},
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "show module adapter infomation",
		Run: func(cmd *cobra.Command, args []string) {
			count := PacketCounter{}
			if CommmandGetResult(moduleId, ADAPTER_CMD_SHOW, &count) {
				fmt.Println("Trident-Adapter Module Running Status:")
				fmt.Printf("\tRX_PACKETS:           %v\n", count.RxPackets)
				fmt.Printf("\tRX_DROP:              %v\n", count.RxDropped)
				fmt.Printf("\tRX_ERROR:             %v\n", count.RxErrors)
				fmt.Printf("\tRX_INVALID:           %v\n", count.RxInvalid)
				fmt.Printf("\tTX_PACKETS:           %v\n", count.TxPackets)
			}
		},
	}
	showPerf := &cobra.Command{
		Use:   "show-perf",
		Short: "show adapter performance information",
		Run: func(cmd *cobra.Command, args []string) {
			last := PacketCounter{}
			if !CommmandGetResult(moduleId, ADAPTER_CMD_SHOW, &last) {
				return
			}
			time.Sleep(1 * time.Second)
			now := PacketCounter{}
			if !CommmandGetResult(moduleId, ADAPTER_CMD_SHOW, &now) {
				return
			}
			fmt.Println("Trident-Adapter Module Performance:")
			fmt.Printf("\tRX_PACKETS/S:             %v\n", now.RxPackets-last.RxPackets)
			fmt.Printf("\tRX_DROPPED/S:             %v\n", now.RxDropped-last.RxDropped)
			fmt.Printf("\tRX_ERRORS/S:              %v\n", now.RxErrors-last.RxErrors)
			fmt.Printf("\tRX_INVALID/S:             %v\n", now.RxInvalid-last.RxInvalid)
			fmt.Printf("\tTX_PACKETS/S:             %v\n", now.TxPackets-last.TxPackets)
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "show trident status",
		Run: func(cmd *cobra.Command, args []string) {
			var result string
			if !CommmandGetResult(moduleId, ADAPTER_CMD_STATUS, &result) {
				return
			}
			fmt.Printf("Tridents Running Status:\n")
			fmt.Printf("%s", result)
		},
	}
	cmd.AddCommand(show)
	cmd.AddCommand(showPerf)
	cmd.AddCommand(status)
	return cmd
}
