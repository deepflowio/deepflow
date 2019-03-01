package dropletctl

import "gitlab.x.lan/yunshan/droplet-libs/debug"

const (
	DROPLETCTL_ADAPTER debug.ModuleId = iota
	DROPLETCTL_QUEUE
	DROPLETCTL_LABELER
	DROPLETCTL_RPC
	DROPLETCTL_LOGLEVEL
	DROPLETCTL_CONFIG
	DROPLETCTL_MAX
)

const (
	DEBUG_MESSAGE_LEN = 4096
)

var ConfigPath string
