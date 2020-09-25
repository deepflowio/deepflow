package receiver

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
)

const (
	TRIDENT_ADAPTER_STATUS_CMD = 12 // 目前1被queue占用, 20被logLeverlCmd占用，其余的可用

	ADAPTER_CMD_STATUS = 1
)

func (c *Receiver) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	buff := bytes.Buffer{}
	switch operate {
	case ADAPTER_CMD_STATUS:
		encoder := gob.NewEncoder(&buff)
		status := fmt.Sprintf("VTAPID TridentIP                                Type Drop LastSeq  LastRemoteTimestamp LastLocalTimestamp  LastDelay LastRecvFromNow FirstSeq FirstRemoteTimestamp FirstLocalTimestamp\n")
		status += fmt.Sprintf("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
		c.statusLock.Lock()
		for _, instance := range c.status {
			status += fmt.Sprintf("%-6d %-40s %-4s %-4d %-8d %-19.19s %-19.19s %-9d %-15d %-8d %-19.19s  %-19.19s\n",
				instance.VTAPID, instance.ip, instance.serverType, c.counter.UDPDropped,
				instance.lastSeq, time.Unix(int64(instance.lastRemoteTimestamp), 0), time.Unix(int64(instance.LastLocalTimestamp), 0),
				instance.LastLocalTimestamp-instance.lastRemoteTimestamp, uint32(time.Now().Unix())-instance.LastLocalTimestamp,
				instance.firstSeq, time.Unix(int64(instance.firstRemoteTimestamp), 0), time.Unix(int64(instance.firstLocalTimestamp), 0))
		}
		c.statusLock.Unlock()

		if err := encoder.Encode(status); err != nil {
			log.Error(err)
			return
		}
		debug.SendToClient(conn, remote, 0, &buff)
	default:
		log.Warningf("Trident Adapter recv unknown command(%v).", operate)
	}
}

func CommmandGetResult(operate uint16, mid debug.ModuleId, output interface{}) bool {
	_, result, err := debug.SendToServer(mid, debug.ModuleOperate(operate), nil)
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

func RegisterTridentStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "adapter",
		Short: "config roze adapter module",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'status'.\n")
		},
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "show trident status",
		Run: func(cmd *cobra.Command, args []string) {
			var result string
			if !CommmandGetResult(ADAPTER_CMD_STATUS, TRIDENT_ADAPTER_STATUS_CMD, &result) {
				fmt.Println("Get Tridents Running Status Failed")
				return
			}
			fmt.Printf("Tridents Running Status(%s):\n", time.Now())
			fmt.Printf("%s", result)
		},
	}
	cmd.AddCommand(status)
	return cmd
}
