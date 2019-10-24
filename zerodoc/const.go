package zerodoc

type MessageType uint8

const (
	MSG_USAGE MessageType = iota
	MSG_PERF
	MSG_GEO
	MSG_FLOW
	_
	MSG_TYPE
	MSG_FPS
	MSG_LOG_USAGE
	MSG_VTAP_USAGE
	_
	MSG_VTAP_SIMPLE

	MSG_INVILID
)

const (
	MAX_STRING_LENGTH = 1024
)
