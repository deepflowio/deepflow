package flowgenerator

import "time"

func flagEqual(flags, target uint8) bool {
	return flags == target
}

func flagContain(flags, target uint8) bool {
	return flags&target > 0
}

func isExceptionFlags(flags uint8, reply bool) bool {
	switch flags & TCP_FLAG_MASK {
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
	timeoutSec time.Duration
	flowState  FlowState
	closed     bool
}

func (f *FlowGenerator) initStateMachineMaster() {
	stateMachineMaster := f.stateMachineMaster
	timeoutConfig := f.TimeoutConfig

	// for FLOW_STATE_RAW
	stateMachineMaster[FLOW_STATE_RAW] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_RAW][TCP_SYN] = &StateValue{timeoutConfig.Opening, FLOW_STATE_OPENING_1, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_SYN]

	stateMachineMaster[FLOW_STATE_RAW][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_FIN]
	stateMachineMaster[FLOW_STATE_RAW][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_FIN]

	stateMachineMaster[FLOW_STATE_RAW][TCP_RST] = &StateValue{timeoutConfig.Opening, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_RST]
	stateMachineMaster[FLOW_STATE_RAW][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_RST]

	stateMachineMaster[FLOW_STATE_RAW][TCP_ACK] = &StateValue{timeoutConfig.Established, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_RAW][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_ACK]
	stateMachineMaster[FLOW_STATE_RAW][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_RAW][TCP_ACK]

	// for FLOW_STATE_OPENING_1
	stateMachineMaster[FLOW_STATE_OPENING_1] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_SYN] = &StateValue{timeoutConfig.Opening, FLOW_STATE_OPENING_1, false}

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN]
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_FIN]

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST] = &StateValue{timeoutConfig.Opening, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST]
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_RST]

	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_ACK] = &StateValue{timeoutConfig.Established, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_ACK]
	stateMachineMaster[FLOW_STATE_OPENING_1][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_1][TCP_ACK]

	// for FLOW_STATE_OPENING_2
	stateMachineMaster[FLOW_STATE_OPENING_2] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_SYN] = &StateValue{timeoutConfig.Opening, FLOW_STATE_OPENING_2, false}

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN]
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_FIN]

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST] = &StateValue{timeoutConfig.Opening, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST]
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_RST]

	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_ACK] = &StateValue{timeoutConfig.Established, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_ACK]
	stateMachineMaster[FLOW_STATE_OPENING_2][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_OPENING_2][TCP_ACK]

	// for FLOW_STATE_ESTABLISHED
	stateMachineMaster[FLOW_STATE_ESTABLISHED] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_SYN] = &StateValue{timeoutConfig.Established, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_SYN]

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN]
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_FIN]

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST] = &StateValue{timeoutConfig.EstablishedRst, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST]
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_RST]

	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_ACK] = &StateValue{timeoutConfig.Established, FLOW_STATE_ESTABLISHED, false}
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_ACK]
	stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_ESTABLISHED][TCP_ACK]

	// for FLOW_STATE_CLOSING_TX1
	stateMachineMaster[FLOW_STATE_CLOSING_TX1] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_SYN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST] = &StateValue{timeoutConfig.Closing, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_ACK] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_ACK]
	stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX1][TCP_ACK]

	// for FLOW_STATE_CLOSING_TX2
	stateMachineMaster[FLOW_STATE_CLOSING_TX2] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_SYN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST] = &StateValue{timeoutConfig.ClosedFin, FLOW_STATE_RESET, true}
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_TX2][TCP_ACK] = &StateValue{timeoutConfig.ClosedFin, FLOW_STATE_CLOSED, true}

	// for FLOW_STATE_CLOSING_RX1
	stateMachineMaster[FLOW_STATE_CLOSING_RX1] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_SYN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST] = &StateValue{timeoutConfig.Closing, FLOW_STATE_RESET, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_ACK] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX1, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_ACK]
	stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX1][TCP_ACK]

	// for FLOW_STATE_CLOSING_RX2
	stateMachineMaster[FLOW_STATE_CLOSING_RX2] = make(map[uint8]*StateValue)

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_SYN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_SYN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_SYN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN]
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_FIN]

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST] = &StateValue{timeoutConfig.ClosedFin, FLOW_STATE_RESET, true}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST]
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST|TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_RST]

	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_ACK] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX2, false}
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_PSH|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_ACK]
	stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineMaster[FLOW_STATE_CLOSING_RX2][TCP_ACK]

	// for FLOW_STATE_RESET
	stateMachineMaster[FLOW_STATE_RESET] = make(map[uint8]*StateValue)
}

func (f *FlowGenerator) initStateMachineSlave() {
	stateMachineSlave := f.stateMachineSlave
	timeoutConfig := f.TimeoutConfig

	// for FLOW_STATE_RAW
	stateMachineSlave[FLOW_STATE_RAW] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_RAW][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_RAW][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_RAW][TCP_FIN]
	stateMachineSlave[FLOW_STATE_RAW][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_RAW][TCP_FIN]

	// for FLOW_STATE_OPENING_1
	stateMachineSlave[FLOW_STATE_OPENING_1] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_SYN|TCP_ACK] = &StateValue{timeoutConfig.Opening, FLOW_STATE_OPENING_2, false}

	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN]
	stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_1][TCP_FIN]

	// for FLOW_STATE_OPENING_2
	stateMachineSlave[FLOW_STATE_OPENING_2] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_SYN|TCP_ACK] = &StateValue{timeoutConfig.Opening, FLOW_STATE_OPENING_2, false}

	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN]
	stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_OPENING_2][TCP_FIN]

	// for FLOW_STATE_ESTABLISHED
	stateMachineSlave[FLOW_STATE_ESTABLISHED] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX1, false}
	stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN]
	stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_ESTABLISHED][TCP_FIN]

	// for FLOW_STATE_CLOSING_TX1
	stateMachineSlave[FLOW_STATE_CLOSING_TX1] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX2, false}
	stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN]
	stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX1][TCP_FIN]

	// for FLOW_STATE_CLOSING_TX2
	stateMachineSlave[FLOW_STATE_CLOSING_TX2] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_ACK] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_TX2, false}
	stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_ACK]
	stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_PSH|TCP_URG|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_TX2][TCP_ACK]

	// for FLOW_STATE_CLOSING_RX1
	stateMachineSlave[FLOW_STATE_CLOSING_RX1] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN] = &StateValue{timeoutConfig.Closing, FLOW_STATE_CLOSING_RX2, false}
	stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN]
	stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN|TCP_PSH|TCP_ACK] = stateMachineSlave[FLOW_STATE_CLOSING_RX1][TCP_FIN]

	// for FLOW_STATE_CLOSING_TX2
	stateMachineSlave[FLOW_STATE_CLOSING_RX2] = make(map[uint8]*StateValue)

	stateMachineSlave[FLOW_STATE_CLOSING_RX2][TCP_ACK] = &StateValue{timeoutConfig.ClosedFin, FLOW_STATE_CLOSED, true}

	// for FLOW_STATE_RESET
	stateMachineSlave[FLOW_STATE_RESET] = make(map[uint8]*StateValue)
}
