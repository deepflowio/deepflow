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

var ConfigPath string
