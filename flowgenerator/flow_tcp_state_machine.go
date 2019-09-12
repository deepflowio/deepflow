package flowgenerator

import (
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func flagContain(flags, target uint8) bool {
	return flags&target > 0
}

func calcCloseType(taggedFlow *TaggedFlow, flowState FlowState) {
	switch flowState {
	case FLOW_STATE_EXCEPTION:
		taggedFlow.CloseType = CloseTypeUnknown
	case FLOW_STATE_OPENING_1:
		taggedFlow.CloseType = CloseTypeServerHalfOpen
	case FLOW_STATE_OPENING_2:
		taggedFlow.CloseType = CloseTypeClientHalfOpen
	case FLOW_STATE_ESTABLISHED:
		taggedFlow.CloseType = CloseTypeTimeout
	case FLOW_STATE_CLOSING_TX1:
		taggedFlow.CloseType = CloseTypeServerHalfClose
	case FLOW_STATE_CLOSING_RX1:
		taggedFlow.CloseType = CloseTypeClientHalfClose
	case FLOW_STATE_CLOSING_TX2:
		fallthrough
	case FLOW_STATE_CLOSING_RX2:
		fallthrough
	case FLOW_STATE_CLOSED:
		taggedFlow.CloseType = CloseTypeTCPFin
	case FLOW_STATE_RESET:
		if flagContain(taggedFlow.FlowMetricsPeerDst.TCPFlags, TCP_RST) {
			taggedFlow.CloseType = CloseTypeTCPServerRst
		} else {
			taggedFlow.CloseType = CloseTypeTCPClientRst
		}
	default:
		log.Warningf("unexcepted 'unknown' close type, flow id is %d", taggedFlow.FlowID)
		taggedFlow.CloseType = CloseTypeUnknown
	}
}

// return true if unexpected flags got
func StatePreprocess(meta *MetaPacket, flags uint8) bool {
	switch flags {
	case TCP_SYN:
		return false
	case TCP_SYN | TCP_ACK:
		return false
	case TCP_FIN:
		return false
	case TCP_FIN | TCP_ACK:
		return false
	case TCP_FIN | TCP_PSH | TCP_ACK:
		return false
	case TCP_RST:
		return false
	case TCP_RST | TCP_ACK:
		return false
	case TCP_RST | TCP_PSH | TCP_ACK:
		return false
	case TCP_ACK:
		return false
	case TCP_PSH | TCP_ACK:
		return false
	case TCP_PSH | TCP_ACK | TCP_URG:
		return false
	default:
		return true
	}
}

type StateValue struct {
	timeout   time.Duration
	flowState FlowState
	closed    bool
}

func (m *FlowMap) initStateMachineMaster() {
	stateMachineMaster := m.stateMachineMaster

	// for FLOW_STATE_RAW
	stateMachineMaster[FLOW_STATE_RAW] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_RAW][TCP_SYN] = &StateValue{openingTimeout, FLOW_STATE_OPENING_1, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_SYN]

	stateMachineMaster[FLOW_STATE_RAW][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_FIN]
	stateMachineMaster[FLOW_STATE_RAW][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_FIN]

	stateMachineMaster[FLOW_STATE_RAW][TCP_RST] = &StateValue{openingTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_RST]
	stateMachineMaster[FLOW_STATE_RAW][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_RST]

	stateMachineMaster[FLOW_STATE_RAW][TCP_ACK] = &StateValue{establishedTimeout, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_ACK]
	stateMachineMaster[FLOW_STATE_RAW][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_ACK]

	// for FLOW_STATE_OPENING_1
	stateMachineMaster[FLOW_STATE_OPENING_1] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_SYN] = &StateValue{openingTimeout, FLOW_STATE_OPENING_1, false}

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN]
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN]

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST] = &StateValue{openingTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST]
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST]

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_ACK] = &StateValue{establishedTimeout, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_ACK]
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_ACK]

	// for FLOW_STATE_OPENING_2
	stateMachineMaster[FLOW_STATE_OPENING_2] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_SYN] = &StateValue{openingTimeout, FLOW_STATE_OPENING_2, false}

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN]
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN]

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST] = &StateValue{openingTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST]
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST]

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_ACK] = &StateValue{establishedTimeout, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_ACK]
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_ACK]

	// for FLOW_STATE_ESTABLISHED
	stateMachineMaster[FLOW_STATE_ESTABLISHED] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_SYN] = &StateValue{establishedTimeout, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_SYN]

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN]
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN]

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST] = &StateValue{establishedRstTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST]
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST]

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_ACK] = &StateValue{establishedTimeout, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_ACK]
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_ACK]

	// for FLOW_STATE_CLOSING_TX1
	stateMachineMaster[FLOW_STATE_CLOSING_TX1] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_SYN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST] = &StateValue{closingTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_ACK] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_ACK]
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_ACK]

	// for FLOW_STATE_CLOSING_TX2
	stateMachineMaster[FLOW_STATE_CLOSING_TX2] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_SYN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST] = &StateValue{closedFinTimeout, FLOW_STATE_RESET, true}
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_ACK] = &StateValue{closedFinTimeout, FLOW_STATE_CLOSED, true}

	// for FLOW_STATE_CLOSING_RX1
	stateMachineMaster[FLOW_STATE_CLOSING_RX1] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_SYN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST] = &StateValue{closingTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_ACK] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_ACK]
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_ACK]

	// for FLOW_STATE_CLOSING_RX2
	stateMachineMaster[FLOW_STATE_CLOSING_RX2] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_SYN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST] = &StateValue{closedFinTimeout, FLOW_STATE_RESET, true}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_ACK] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_ACK]
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_ACK]

	// for FLOW_STATE_CLOSED
	stateMachineMaster[FLOW_STATE_CLOSED] = make(map[uint8]*StateValue)

	// for FLOW_STATE_RESET
	stateMachineMaster[FLOW_STATE_RESET] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_RESET][TCP_SYN] = &StateValue{exceptionTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_RESET][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_RESET][TCP_SYN]

	stateMachineMaster[FLOW_STATE_RESET][TCP_FIN] = &StateValue{exceptionTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_RESET][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_RESET][TCP_FIN]
	stateMachineMaster[FLOW_STATE_RESET][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RESET][TCP_FIN]

	stateMachineMaster[FLOW_STATE_RESET][TCP_RST] = &StateValue{exceptionTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_RESET][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_RESET][TCP_RST]
	stateMachineMaster[FLOW_STATE_RESET][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RESET][TCP_RST]

	stateMachineMaster[FLOW_STATE_RESET][TCP_ACK] = &StateValue{exceptionTimeout, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_RESET][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RESET][TCP_ACK]
	stateMachineMaster[FLOW_STATE_RESET][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_RESET][TCP_ACK]

	// for FLOW_STATE_EXCEPTION
	stateMachineMaster[FLOW_STATE_EXCEPTION] = make(map[uint8]*StateValue)
}

func (m *FlowMap) initStateMachineSlave() {
	stateMachineSlave := m.stateMachineSlave

	// for FLOW_STATE_RAW
	stateMachineSlave[FLOW_STATE_RAW] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_RAW][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_RAW][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_RAW][TCP_FIN]
	stateMachineSlave[FLOW_STATE_RAW][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_RAW][TCP_FIN]

	// for FLOW_STATE_OPENING_1
	stateMachineSlave[FLOW_STATE_OPENING_1] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_SYN|TCP_ACK] = &StateValue{openingTimeout, FLOW_STATE_OPENING_2, false}

	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN]
	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN]

	// for FLOW_STATE_OPENING_2
	stateMachineSlave[FLOW_STATE_OPENING_2] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_SYN|TCP_ACK] = &StateValue{openingTimeout, FLOW_STATE_OPENING_2, false}

	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN]
	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN]

	// for FLOW_STATE_ESTABLISHED
	stateMachineSlave[FLOW_STATE_ESTABLISHED] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN]
	stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN]

	// for FLOW_STATE_CLOSING_TX1
	stateMachineSlave[FLOW_STATE_CLOSING_TX1] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX2, false}
	stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN]
	stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN]

	// for FLOW_STATE_CLOSING_TX2
	stateMachineSlave[FLOW_STATE_CLOSING_TX2] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_ACK] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_TX2, false}
	stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_ACK]
	stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_ACK]

	// for FLOW_STATE_CLOSING_RX1
	stateMachineSlave[FLOW_STATE_CLOSING_RX1] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN] = &StateValue{closingTimeout, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN]
	stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN]

	// for FLOW_STATE_CLOSING_RX2
	stateMachineSlave[FLOW_STATE_CLOSING_RX2] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_RX2][TCP_ACK] = &StateValue{closedFinTimeout, FLOW_STATE_CLOSED, true}

	// for FLOW_STATE_CLOSED
	stateMachineSlave[FLOW_STATE_CLOSED] = make(map[uint8]*StateValue)

	// for FLOW_STATE_RESET
	stateMachineSlave[FLOW_STATE_RESET] = make(map[uint8]*StateValue)

	// for FLOW_STATE_EXCEPTION
	stateMachineSlave[FLOW_STATE_EXCEPTION] = make(map[uint8]*StateValue)
}
