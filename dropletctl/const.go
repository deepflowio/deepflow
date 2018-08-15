package dropletctl

import (
	"bytes"
	"net"

	"github.com/spf13/cobra"
)

type RegisterCommmandLine func() *cobra.Command

type DropletCtlModuleId uint16
type DropletCtlModuleOperate uint16

const (
	DROPLETCTL_ADAPTER DropletCtlModuleId = iota
	DROPLETCTL_QUEUE
	DROPLETCTL_MAX
)

const (
	DROPLETCTL_PORT = 9527
	DROPLETCTL_IP   = "127.0.0.1"
)

type CommandLineProcess interface {
	RecvCommand(conn *net.UDPConn, port int, operate uint16, arg *bytes.Buffer)
}

var RecvHandlers = [DROPLETCTL_MAX]CommandLineProcess{}
var RegisterHandlers = [DROPLETCTL_MAX]RegisterCommmandLine{}
