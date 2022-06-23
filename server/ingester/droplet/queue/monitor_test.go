package queue

import (
	"testing"
)

func TestMonitor(t *testing.T) {
	m := &Monitor{}

	m.init("1", nil)
	m.debugSwitch(true)
	if !m.isDebugOn() {
		t.Error("debugSwitch error")
	}
	m.TurnOffDebug()
	if m.isDebugOn() {
		t.Error("TurnOffDebug error")
	}
	m.unmarshal("1")
}
