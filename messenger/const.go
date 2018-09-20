package messenger

type MessageType uint8

const (
	MSG_USAGE MessageType = iota
	MSG_PERF
	MSG_GEO
	MSG_FLOW
	MSG_PLATFORM
	MSG_CONSOLE_LOG
	MSG_TYPE
)
