package rpc

import (
	"net"
)

type StubListener struct {
	onMacTupleChange func([][2]net.HardwareAddr)
	onConfigChange   func(RuntimeConfig) error
}

func (l *StubListener) OnMacTupleChange(macTuples [][2]net.HardwareAddr) {
	if l.onMacTupleChange != nil {
		l.onMacTupleChange(macTuples)
	}
}

func (l *StubListener) OnConfigChange(cfg RuntimeConfig) error {
	if l.onConfigChange != nil {
		return l.onConfigChange(cfg)
	}
	return nil
}
