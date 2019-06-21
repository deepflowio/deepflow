package adapter

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
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
		if err := encoder.Encode(adapter.stats); err != nil {
			log.Error(err)
			return
		}
		debug.SendToClient(conn, remote, 0, &buff)
		break
	case ADAPTER_CMD_STATUS:
		encoder := gob.NewEncoder(&buff)
		status := ""
		adapter.instancesLock.Lock()
		for key, instance := range adapter.instances {
			status += fmt.Sprintf("Host: %16s Seq: %10d Cache: %2d Timestamp: %30s\n",
				IpFromUint32(key), instance.seq, instance.cacheCount, time.Unix(int64(instance.timestamp/time.Second), int64(instance.timestamp%time.Second)))
		}
		adapter.instancesLock.Unlock()

		if err := encoder.Encode(status); err != nil {
			log.Error(err)
			return
		}
		debug.SendToClient(conn, remote, 0, &buff)
	default:
		log.Warningf("Trident Adapter recv unknown command(%v).", operate)
	}
}

func CommmandGetResult(operate uint16, output interface{}) bool {
	_, result, err := debug.SendToServer(dropletctl.DROPLETCTL_ADAPTER, debug.ModuleOperate(operate), nil)
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

func RegisterCommand() *cobra.Command {
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
			if CommmandGetResult(ADAPTER_CMD_SHOW, &count) {
				fmt.Println("Trident-Adapter Module Running Status:")
				fmt.Printf("\tRX_PACKETS:           %v\n", count.RxPackets)
				fmt.Printf("\tRX_DROP:              %v\n", count.RxDropped)
				fmt.Printf("\tRX_ERROR:             %v\n", count.RxErrors)
				fmt.Printf("\tRX_CACHE:             %v\n", count.RxCached)
				fmt.Printf("\tTX_PACKETS:           %v\n", count.TxPackets)
				fmt.Printf("\tTX_DROP:              %v\n", count.TxDropped)
				fmt.Printf("\tTX_ERROR:             %v\n", count.TxErrors)
			}
		},
	}
	showPerf := &cobra.Command{
		Use:   "show-perf",
		Short: "show adapter performance information",
		Run: func(cmd *cobra.Command, args []string) {
			last := PacketCounter{}
			if !CommmandGetResult(ADAPTER_CMD_SHOW, &last) {
				return
			}
			time.Sleep(1 * time.Second)
			now := PacketCounter{}
			if !CommmandGetResult(ADAPTER_CMD_SHOW, &now) {
				return
			}
			fmt.Println("Trident-Adapter Module Performance:")
			fmt.Printf("\tRX_PACKETS/S:             %v\n", now.RxPackets-last.RxPackets)
			fmt.Printf("\tRX_DROPPED/S:             %v\n", now.RxDropped-last.RxDropped)
			fmt.Printf("\tRX_ERRORS/S:              %v\n", now.RxErrors-last.RxErrors)
			fmt.Printf("\tRX_CACHED/S:              %v\n", now.RxCached-last.RxCached)
			fmt.Printf("\tTX_PACKETS/S:             %v\n", now.TxPackets-last.TxPackets)
			fmt.Printf("\tTX_DROPPED/S:             %v\n", now.TxDropped-last.TxDropped)
			fmt.Printf("\tTX_ERRORS/S:              %v\n", now.TxErrors-last.TxErrors)
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "show trident status",
		Run: func(cmd *cobra.Command, args []string) {
			var result string
			if !CommmandGetResult(ADAPTER_CMD_STATUS, &result) {
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
