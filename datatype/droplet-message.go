package datatype

// 本消息格式仅用于同droplet通信:
//     1. FrameSize用于粘包，为了简化包头压缩算法逻辑，UDP发送时也需要预留FrameSize但是内容可以为0
//     2. MessageType标注消息类型
//     3. MessageValue为具体的消息内容
// --------------------------------------------------------
// | FrameSize(2B) | MessageType(1B) |  MessageValue(...) |
// --------------------------------------------------------
const (
	MESSAGE_TYPE_COMPRESS = iota
	MESSAGE_TYPE_SYSLOG
	MESSAGE_TYPE_STATSD
	MESSAGE_TYPE_MAX
)

const (
	DROPLET_PORT = "20033"
)

const (
	MESSAGE_FRAME_SIZE_OFFSET = 0
	MESSAGE_TYPE_OFFSET       = 2
	MESSAGE_VALUE_OFFSET      = 3
)
